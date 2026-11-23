//! Scan a pinned, authenticated v10 archive and rebuild spendable wallet inputs.
use crate::{
    capsule::{self, Receiver, WalletKeys},
    package::{self, Delivery, Pin},
    payment::Payment,
};
use anyhow::{ensure, Context, Result};
use reqwest::blocking::Client;
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path, time::Duration};
use tondi_consensus_core::{
    genesis::Genesis,
    snapshot::{CheckpointChain, CheckpointExtensionReader},
    state::State,
};
use tondi_vm::{
    builder::{AuthDescriptor, DraftInput},
    schnorr_auth,
    settlement::{OrderingRecord, Outcome},
    Hash32, OutPoint, Transition, ValidationScriptRef, VALIDATION_SCRIPT_DATA,
};

struct Recovered {
    history: Vec<u8>,
    payment: Payment,
    point: OutPoint,
}

fn rebuild(
    plain: &[u8],
    receiver: &Receiver,
    genesis: &Genesis,
    tx: &Transition,
    spent: &BTreeMap<Hash32, Hash32>,
) -> Result<Recovered> {
    let (history, payment) = capsule::unpack(plain)?;
    ensure!(payment.receiver == *receiver, "capsule receiver differs");
    if history.starts_with(crate::recursive::MAGIC) {
        let point = OutPoint::new(tx.id(), payment.vout);
        let history = crate::recursive::receive(history, &payment, tx)?;
        return Ok(Recovered { history, payment, point });
    }
    let expected = payment.articles.parse()?;
    let dir = tempfile::tempdir()?;
    let mut contract = package::read_contract(history, dir.path(), expected)?;
    let path = dir.path().join("next.rgt");
    payment.export_history(&mut contract, tx.clone(), &path)?;
    let history = fs::read(path)?;
    let checked = tempfile::tempdir()?;
    let contract = package::read_contract(&history, checked.path(), expected)?;
    for (id, witness) in package::required_witnesses(&contract, genesis)? {
        ensure!(
            spent.get(&Hash32::from_bytes(id.0))
                == Some(&tondi_vm::codec::hash("RGT/certified-record/v1", witness.record())),
            "uncertified predecessor witness"
        );
    }
    let point = OutPoint::new(tx.id(), payment.vout);
    package::check_delivery(
        &contract,
        &Delivery {
            point,
            auth: receiver.auth,
            allocation: payment.allocation.clone(),
        },
    )?;
    Ok(Recovered { history, payment, point })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    genesis: Hash32,
    #[serde(with = "tondi_vm::codec::u64_decimal")]
    certified_through: u64,
}

pub fn restore(
    genesis: &Genesis,
    pin: Pin,
    keys: &WalletKeys,
    rpc: &str,
    output: &Path,
) -> Result<()> {
    ensure!(!output.exists(), "choose a new wallet snapshot directory");
    let rpc = rpc.trim_end_matches('/');
    let receiver = keys.receiver(genesis);
    let http = Client::builder().timeout(Duration::from_secs(30)).build()?;
    let status: Status = package::get(&http, format!("{rpc}/v1/status"))?;
    ensure!(
        status.genesis == genesis.id() && status.certified_through >= pin.index,
        "archive is behind the requested pin or on another chain"
    );
    let chain = CheckpointChain::new(genesis.clone())?;
    let version = chain.commitment_version();
    let mut chain = chain.v10_reader();
    let mut ledger = State::new(genesis.clone())?;
    let mut pinned = pin.index == 0 && pin.id == genesis.id();
    let mut spent = BTreeMap::new();
    let mut found = BTreeMap::new();
    let mut invalid = 0usize;
    while chain.index() < status.certified_through {
        let limit = (status.certified_through - chain.index())
            .min(CheckpointExtensionReader::MAX_HEADERS as u64);
        let extension = package::fetch_extension(&http, rpc, &mut chain, limit)?;
        for h in &extension.headers {
            pinned |= h.commit_index == pin.index && h.id() == pin.id;
            let body = package::fetch_body(&http, rpc, h)
                .with_context(|| format!("incomplete archive at checkpoint {}", h.commit_index))?;
            ensure!(
                body.header == *h
                    && body.input_root() == h.input_root
                    && body.execution_root_for(version)? == h.execution_root,
                "invalid archived checkpoint body"
            );
            body.validate_outcomes()?;
            let replay =
                ledger.replay_batch(&body, &tondi_consensus::crypto::KarmaDagEvidence, None)?;
            ensure!(
                replay.header == *h && replay.outcomes == body.outcomes,
                "archive replay differs from certified execution"
            );
            for (record, outcome) in body.records.iter().zip(&body.outcomes) {
                let Outcome::Transaction(ok) = outcome else {
                    continue;
                };
                let record = tondi_consensus_core::granted_record::body(record)?;
                let OrderingRecord::Transaction(tx) = OrderingRecord::decode(record)? else {
                    anyhow::bail!("inconsistent transaction outcome")
                };
                ensure!(
                    ok.transaction == tx.id() && tx.network == genesis.network,
                    "inconsistent archived spend"
                );
                spent.insert(tx.id(), tondi_vm::codec::hash("RGT/certified-record/v1", record));
                for input in tx.inputs.iter().filter(|i| i.consumes()) {
                    found.retain(|(_, point), _| *point != input.outpoint());
                }
                for c in tx.checks.iter().filter(|c| {
                    c.validation_script
                        == ValidationScriptRef::standard(VALIDATION_SCRIPT_DATA).id()
                }) {
                    let Some(plain) = keys.decrypt(&receiver, &c.data) else {
                        continue;
                    };
                    match rebuild(&plain, &receiver, genesis, &tx, &spent) {
                        Ok(asset) => {
                            found.insert((asset.payment.articles.clone(), asset.point), asset);
                        }
                        Err(error) => {
                            if error
                                .chain()
                                .filter_map(|e| e.downcast_ref::<std::io::Error>())
                                .any(|io| {
                                    matches!(
                                        io.kind(),
                                        std::io::ErrorKind::PermissionDenied
                                            | std::io::ErrorKind::StorageFull
                                            | std::io::ErrorKind::ReadOnlyFilesystem
                                    )
                                })
                            {
                                return Err(error.context("could not stage recovered RGT state"));
                            }
                            invalid += 1;
                        }
                    }
                }
            }
        }
    }
    ensure!(pinned, "trusted checkpoint missing or mismatched");
    let scan_index = chain.index();
    let scan_head = chain.head();
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = tempfile::tempdir_in(parent)?;
    let mut assets = Vec::new();
    for asset in found.into_values() {
        let Some(entry) = ledger.notes.get(&asset.point) else {
            continue;
        };
        ensure!(entry.note.auth.script_hash == receiver.auth, "recovered Note has wrong Auth");
        let pubkey = secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, &keys.spend);
        let (_, script) = schnorr_auth(pubkey.x_only_public_key().0.serialize());
        let input = DraftInput {
            outpoint: asset.point,
            entry: entry.as_ref().clone(),
            auth: Some(AuthDescriptor { script }),
            since: 0,
            consume: true,
        };
        let ext =
            if asset.history.starts_with(crate::recursive::PENDING) { "rgtstep" } else { "rgt" };
        let name =
            format!("{}-{}-{}.{ext}", asset.point.transaction_id, asset.point.index, assets.len());
        crate::cli::save(&staging.path().join(&name), &asset.history)?;
        assets.push(serde_json::json!({"history":name,"articles":asset.payment.articles,"allocation":asset.payment.allocation,"draftInput":input,
            "liveCheckpoint":scan_head,"liveIndex":scan_index}));
    }
    let wallet = serde_json::json!({"protocol":"RGT/1","genesis":genesis.id(),"scannedThrough":scan_index,"scannedHead":scan_head,
        "invalidCapsules":invalid,"assets":assets});
    crate::cli::save(&staging.path().join("wallet.json"), &serde_json::to_vec_pretty(&wallet)?)?;
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staging.path(),
        rustix::fs::CWD,
        output,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    {
        fs::create_dir(output)?;
        let result = (|| -> std::io::Result<()> {
            for asset in &assets {
                let name = asset["history"].as_str().unwrap();
                fs::rename(staging.path().join(name), output.join(name))?;
            }
            fs::rename(staging.path().join("wallet.json"), output.join("wallet.json"))
        })();
        if let Err(error) = result {
            for asset in &assets {
                let _ = fs::remove_file(output.join(asset["history"].as_str().unwrap()));
            }
            let _ = fs::remove_dir(output);
            return Err(error.into());
        }
    }
    println!("Recovered {} live RGT allocations through checkpoint {scan_index} ({invalid} invalid addressed capsules)", assets.len());
    Ok(())
}
