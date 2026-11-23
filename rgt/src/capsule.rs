//! Recipient-encrypted transfer histories and recursive wallet snapshots for RGT.
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{ensure, Context, Result};
use hkdf::Hkdf;
use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey, SECP256K1};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tondi_consensus_core::genesis::Genesis;
use tondi_vm::{schnorr_auth, Hash32};
use zeroize::Zeroizing;

use crate::payment::Payment;

pub const MAGIC: &[u8; 8] = b"RGTCAP\0\x01";
const HEADER: usize = 8 + 33 + 12;
const KEY_DOMAIN: &[u8] = b"RGT/capsule/secp256k1-HKDF-SHA256-AES256GCM/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receiver {
    pub genesis: Hash32,
    pub network: Hash32,
    pub view_key: String,
    pub auth: Hash32,
}

pub struct WalletKeys {
    view: SecretKey,
    pub(crate) spend: SecretKey,
}

impl WalletKeys {
    /// Accept 32–64 bytes of hex wallet seed or an English BIP39 phrase.
    pub fn derive(secret: &str, genesis: &Genesis) -> Result<Self> {
        let seed = Zeroizing::new(if secret.split_whitespace().count() > 1 {
            let phrase = bip39::Mnemonic::parse_in(bip39::Language::English, secret)
                .map_err(|_| anyhow::anyhow!("invalid English mnemonic"))?;
            phrase.to_seed("").to_vec()
        } else {
            hex::decode(secret).context("invalid wallet seed encoding")?
        });
        ensure!((32..=64).contains(&seed.len()), "expected 32–64 seed bytes");
        let hkdf = Hkdf::<Sha256>::new(Some(&genesis.id().as_bytes()), &seed);
        let derive = |role: &[u8]| -> Result<SecretKey> {
            for counter in 0u8..=255 {
                let mut bytes = Zeroizing::new([0u8; 32]);
                hkdf.expand_multi_info(&[b"RGT/wallet/v1/", role, &[counter]], bytes.as_mut())
                    .expect("32-byte HKDF output");
                if let Ok(key) = SecretKey::from_slice(bytes.as_ref()) {
                    return Ok(key);
                }
            }
            anyhow::bail!("wallet key derivation failed")
        };
        Ok(Self { view: derive(b"view")?, spend: derive(b"spend")? })
    }

    pub fn receiver(&self, genesis: &Genesis) -> Receiver {
        let spend = PublicKey::from_secret_key(SECP256K1, &self.spend);
        Receiver {
            genesis: genesis.id(),
            network: genesis.network,
            view_key: PublicKey::from_secret_key(SECP256K1, &self.view).to_string(),
            auth: schnorr_auth(spend.x_only_public_key().0.serialize())
                .0
                .script_hash,
        }
    }

    pub fn decrypt(&self, network: &Receiver, data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if data.len() < HEADER + 16 || !data.starts_with(MAGIC) {
            return None;
        }
        let epk = PublicKey::from_slice(&data[8..41]).ok()?;
        let cipher = cipher(&SharedSecret::new(&epk, &self.view), network, &data[..HEADER]).ok()?;
        cipher
            .decrypt(
                Nonce::from_slice(&data[41..HEADER]),
                Payload { msg: &data[HEADER..], aad: &data[..HEADER] },
            )
            .ok()
            .map(Zeroizing::new)
    }
}

fn cipher(shared: &SharedSecret, receiver: &Receiver, header: &[u8]) -> Result<Aes256Gcm> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&receiver.genesis.as_bytes()), shared.as_ref())
        .expand_multi_info(
            &[
                KEY_DOMAIN,
                &receiver.network.as_bytes(),
                receiver.view_key.as_bytes(),
                &receiver.auth.as_bytes(),
                header,
            ],
            key.as_mut(),
        )
        .expect("32-byte HKDF output");
    Ok(Aes256Gcm::new_from_slice(key.as_ref()).expect("AES-256 key"))
}

pub fn encrypt(payment: &Payment, history: &[u8]) -> Result<Vec<u8>> {
    let receiver = &payment.receiver;
    let view: PublicKey = receiver.view_key.parse()?;
    ensure!(view.to_string() == receiver.view_key, "noncanonical receiver public key");
    let ephemeral = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let mut header = MAGIC.to_vec();
    header.extend_from_slice(&PublicKey::from_secret_key(SECP256K1, &ephemeral).serialize());
    header.extend_from_slice(&rand::random::<[u8; 12]>());
    let cipher = cipher(&SharedSecret::new(&view, &ephemeral), receiver, &header)?;
    let mut plain = Zeroizing::new(Vec::new());
    plain.extend_from_slice(&u32::try_from(history.len())?.to_le_bytes());
    plain.extend_from_slice(history);
    serde_json::to_writer(&mut *plain, payment)?;
    ensure!(
        HEADER + plain.len() + 16 < tondi_vm::resources::MAX_TRANSACTION_BYTES,
        "full-history capsule exceeds native transaction limit"
    );
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&header[41..]), Payload { msg: &plain, aad: &header })
        .map_err(|_| anyhow::anyhow!("capsule encryption failed"))?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

pub fn unpack(plain: &[u8]) -> Result<(&[u8], Payment)> {
    let len = u32::from_le_bytes(plain.get(..4).context("truncated capsule")?.try_into()?) as usize;
    let (history, invoice) = plain[4..]
        .split_at_checked(len)
        .context("invalid capsule history length")?;
    Ok((history, serde_json::from_slice(invoice)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payment::Allocation;
    use tondi_vm::OutPoint;

    #[test]
    fn capsule_binds_recipient_genesis_and_contents() {
        let keys = WalletKeys {
            view: SecretKey::from_slice(&[17; 32]).unwrap(),
            spend: SecretKey::from_slice(&[23; 32]).unwrap(),
        };
        let receiver = Receiver {
            genesis: 1.into(),
            network: 2.into(),
            view_key: PublicKey::from_secret_key(SECP256K1, &keys.view).to_string(),
            auth: 3.into(),
        };
        let invoice = Payment {
            articles: "sample".into(),
            input: OutPoint::new(4.into(), 0),
            vout: 0,
            receiver: receiver.clone(),
            blinding: 5.into(),
            allocation: Allocation { state: "amount".into(), value: 100u64.into() },
        };
        let frame = encrypt(&invoice, b"private history").unwrap();
        assert_ne!(frame, encrypt(&invoice, b"private history").unwrap());
        let plain = keys.decrypt(&receiver, &frame).unwrap();
        let (history, payment) = unpack(&plain).unwrap();
        assert_eq!(history, b"private history");
        assert_eq!(payment.input, invoice.input);
        let wrong = Receiver { genesis: 6.into(), ..receiver.clone() };
        assert!(keys.decrypt(&wrong, &frame).is_none());
        let unrelated = WalletKeys { view: keys.spend, spend: keys.view };
        assert!(unrelated.decrypt(&receiver, &frame).is_none());
        for i in [0, 8, 41, HEADER, frame.len() - 1] {
            let mut broken = frame.clone();
            broken[i] ^= 1;
            assert!(keys.decrypt(&receiver, &broken).is_none());
        }
        assert!(keys.decrypt(&receiver, &frame[..HEADER]).is_none());
    }
}
