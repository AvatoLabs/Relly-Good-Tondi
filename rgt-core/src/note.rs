//! The RGT operation commits to blinded output definitions before a Tondi TxID exists.
//! Output zero carries a single operation commitment. Its Auth stays spendable.
use std::fmt;

use crate::{NoClientWitness, PublishedWitness, RgtSeal, RgtSealDef, SealWitness, SingleUseSeal};
use amplify::{confinement::Confined, Bytes32};
use anyhow::{ensure, Result};
use tondi_vm::{codec, settlement::OrderingRecord, Facet, Hash32, Note, OutPoint, Transition};
use ultrasonic::AuthToken;

/// Strict type library for the native seal wire representation.
pub const LIB: &str = "RgtTondiV10";
/// User Facet key for the RGT operation commitment.
pub const RGT_FACET: u16 = 0x5254;
type RecordBytes = Confined<Vec<u8>, 0, { tondi_vm::settlement::MAX_ORDINARY_ORDERING_BYTES }>;

/// Strict representation of a native Tondi transaction ID.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB)]
pub struct NoteTxid(#[doc = "Native body digest."] pub [u8; 32]);

impl From<[u8; 32]> for NoteTxid {
    fn from(id: [u8; 32]) -> Self {
        Self(id)
    }
}
impl From<NoteTxid> for [u8; 32] {
    fn from(id: NoteTxid) -> Self {
        id.0
    }
}
impl fmt::Display for NoteTxid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Hash32::from_bytes(self.0).fmt(f)
    }
}

/// A fully resolved Note outpoint.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB)]
pub struct NoteSeal {
    /// Transaction creating the Note.
    pub txid: NoteTxid,
    /// Index in the creating transaction.
    pub vout: u32,
}

impl NoteSeal {
    /// Convert to the native VM outpoint.
    pub fn point(self) -> OutPoint {
        OutPoint::new(Hash32::from_bytes(self.txid.into()), self.vout)
    }
}

impl fmt::Display for NoteSeal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

/// Disclosure of a blinded successor or an existing Note.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Eq, PartialEq, StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB)]
pub struct Opening {
    /// Set for an existing Note, absent for an output of the transaction being planned.
    pub txid: Option<NoteTxid>,
    /// Index in the creating transaction.
    pub vout: u32,
    /// Expected Note authorization script hash.
    pub auth: Bytes32,
    /// Per-delivery random blinding.
    pub blinding: Bytes32,
}

impl fmt::Display for Opening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.auth_token())
    }
}

impl RgtSealDef for Opening {
    type Src = NoteSeal;

    fn auth_token(&self) -> AuthToken {
        let mut bytes = Vec::new();
        bytes.push(u8::from(self.txid.is_some()));
        if let Some(txid) = self.txid {
            bytes.extend_from_slice(&txid.0);
        }
        bytes.extend_from_slice(&self.vout.to_le_bytes());
        bytes.extend_from_slice(self.auth.as_ref());
        bytes.extend_from_slice(self.blinding.as_ref());
        let hash = codec::hash("RGT/Tondi-v10/note-seal/v1", &bytes);
        AuthToken::from_byte_array(hash.as_bytes()[..30].try_into().unwrap())
    }

    fn resolve(&self, witness_id: NoteTxid) -> NoteSeal {
        NoteSeal { txid: self.txid.unwrap_or(witness_id), vout: self.vout }
    }

    fn to_src(&self) -> Option<NoteSeal> {
        self.txid.map(|txid| self.resolve(txid))
    }
}

fn commitment(opid: [u8; 32]) -> Hash32 {
    codec::hash("RGT/Tondi-v10/operation/v1", &opid)
}

/// Add the operation commitment before preparing or signing the native transaction.
pub fn anchor(outputs: &mut [Note], opid: [u8; 32]) -> Result<()> {
    ensure!(
        outputs
            .iter()
            .all(|n| n.facets.iter().all(|f| f.key != RGT_FACET)),
        "RGT anchor already present"
    );
    let output = outputs
        .first_mut()
        .ok_or_else(|| anyhow::anyhow!("missing anchor Note"))?;
    output
        .facets
        .push(Facet::new(RGT_FACET, commitment(opid).as_bytes().to_vec()));
    output.facets.sort_by_key(|f| f.key);
    Ok(())
}

/// Body ID and exact signed Telegraph ordering record.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Eq, PartialEq, StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB)]
pub struct NoteWitness {
    txid: NoteTxid,
    record: RecordBytes,
}

impl NoteWitness {
    /// Capture the canonical native ordering envelope.
    pub fn new(tx: Transition) -> Result<Self> {
        Ok(Self {
            txid: tx.id().as_bytes().into(),
            record: RecordBytes::try_from(OrderingRecord::Transaction(tx).encode())?,
        })
    }

    /// Canonical bytes matched against the certified body.
    pub fn record(&self) -> &[u8] {
        &self.record
    }

    /// Decode the native transaction and verify its body ID.
    pub fn transaction(&self) -> Result<Transition> {
        let OrderingRecord::Transaction(tx) = OrderingRecord::decode(self.record())? else {
            anyhow::bail!("expected an ordinary Tondi transaction")
        };
        ensure!(tx.id().as_bytes() == <[u8; 32]>::from(self.txid), "RGT witness TxID mismatch");
        Ok(tx)
    }
}

impl SingleUseSeal for NoteSeal {
    type Message = [u8; 32];
    type PubWitness = NoteWitness;
    type CliWitness = NoClientWitness<Self>;
    fn is_included(&self, _: Self::Message, witness: &SealWitness<Self>) -> bool {
        witness.published.transaction().is_ok_and(|tx| {
            tx.inputs
                .iter()
                .any(|i| i.consumes() && i.outpoint() == self.point())
        })
    }
}

/// The envelope or its operation commitment is invalid.
#[derive(Debug, Clone)]
pub struct InvalidWitness;
impl fmt::Display for InvalidWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid Tondi v10 RGT anchor or envelope")
    }
}
impl std::error::Error for InvalidWitness {}

impl PublishedWitness<NoteSeal> for NoteWitness {
    type PubId = NoteTxid;
    type Error = InvalidWitness;
    fn pub_id(&self) -> NoteTxid {
        self.txid
    }
    fn verify_commitment(&self, opid: [u8; 32]) -> Result<(), Self::Error> {
        let tx = self.transaction().map_err(|_| InvalidWitness)?;
        let expected = Facet::new(RGT_FACET, commitment(opid).as_bytes().to_vec());
        let mut anchors = tx.outputs.iter().enumerate().flat_map(|(index, n)| {
            n.facets
                .iter()
                .filter(|f| f.key == RGT_FACET)
                .map(move |f| (index, f))
        });
        if anchors.next() == Some((0, &expected)) && anchors.next().is_none() {
            Ok(())
        } else {
            Err(InvalidWitness)
        }
    }
}

impl RgtSeal for NoteSeal {
    type Definition = Opening;
    type Published = NoteWitness;
    type Client = NoClientWitness<Self>;
    type WitnessId = NoteTxid;
}

/// Strict type definitions for data bound to the native Note ledger.
#[cfg(feature = "stl")]
pub fn note_stl() -> strict_types::TypeLib {
    use strict_types::{stl::std_stl, LibBuilder};
    LibBuilder::with(libname!(LIB), [std_stl().to_dependency_types()])
        .transpile::<NoteSeal>()
        .transpile::<Opening>()
        .transpile::<NoteWitness>()
        .compile()
        .expect("invalid Note seal schema")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use secp256k1::{Keypair, SECP256K1};
    use tondi_vm::{
        builder::{AuthDescriptor, DraftInput, NativeDraft},
        schnorr_auth, Input, Note, ResolvedInput,
    };

    pub(crate) fn transaction(point: OutPoint, opid: Option<[u8; 32]>) -> Transition {
        let key = Keypair::from_seckey_slice(SECP256K1, &[1; 32]).unwrap();
        let (auth, script) = schnorr_auth(key.x_only_public_key().0.serialize());
        let mut draft = NativeDraft {
            network: 1.into(),
            inputs: vec![DraftInput {
                outpoint: point,
                entry: ResolvedInput {
                    note: Note::plain(8_000_000, auth),
                    birth_epoch: 0,
                    birth_time_seconds: 0,
                    is_reward: false,
                },
                auth: Some(AuthDescriptor { script }),
                consume: true,
                since: 0,
            }],
            outputs: vec![Note::plain(7_000_000, auth)],
            programs: vec![],
            state_creations: vec![],
            validation_scripts: vec![],
            payload: vec![],
        };
        if let Some(opid) = opid {
            anchor(&mut draft.outputs, opid).unwrap();
        }
        draft.prepare().unwrap().transaction
    }

    #[test]
    fn witness_requires_exact_message_consumption_and_unique_anchor() {
        let seal = NoteSeal { txid: NoteTxid([5; 32]), vout: 4 };
        let opid = [9; 32];
        let tx = transaction(seal.point(), Some(opid));
        let witness = |tx| SealWitness::<NoteSeal>::new(NoteWitness::new(tx).unwrap(), Default::default());
        assert!(witness(tx.clone()).verify_seal_closing(seal, opid).is_ok());
        assert!(witness(tx.clone())
            .verify_seal_closing(seal, [1; 32])
            .is_err());
        let mut referenced = tx.clone();
        referenced.edit_body().inputs[0] = Input::Reference { previous_outpoint: seal.point() };
        assert!(witness(referenced).verify_seal_closing(seal, opid).is_err());
        let mut duplicate = tx.clone();
        duplicate.edit_body().outputs.push(tx.outputs[0].clone());
        assert!(witness(duplicate).verify_seal_closing(seal, opid).is_err());
        let mut mismatch = witness(tx);
        mismatch.published.txid = NoteTxid([0; 32]);
        assert!(mismatch.verify_seal_closing(seal, opid).is_err());
    }
}
