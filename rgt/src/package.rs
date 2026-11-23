//! A strict RGT history followed by the evidence for its published witnesses.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use reqwest::blocking::Client;
use rgt::{ArticlesId, Contract, TransferHistory, HISTORY_MAGIC_NUMBER, HISTORY_VERSION};
use rgt_persist_fs::{PileFs, StockFs};
use serde::{Deserialize, Serialize};
use strict_encoding::{StrictDecode, StrictReader};
use tondi_consensus_core::{
    certification::Attestation,
    committee::Committee,
    genesis::Genesis,
    snapshot::{CheckpointChain, CheckpointExtensionReader},
    state::ExecutedCommit,
};
use tondi_vm::{
    settlement::{Header, Outcome},
    Hash32, OutPoint,
};

use rgt::note::{NoteSeal, NoteTxid};

pub type NativeContract = Contract<StockFs, PileFs<NoteSeal>>;
const MAGIC: &[u8; 8] = b"RGTV10\0\x01";
pub const MAX_PACKAGE: usize = 64 << 20;
const MAX_RESPONSE: usize = tondi_consensus::receipt::MAX_CHECKPOINT_BODY_BYTES;

pub fn read_bounded(reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "input exceeds {limit} bytes");
    Ok(bytes)
}

pub fn read_contract(rgt: &[u8], dir: &Path, expected: ArticlesId) -> Result<NativeContract> {
    ensure!(
        rgt.starts_with(&HISTORY_MAGIC_NUMBER.to_be_bytes())
            && rgt.get(8..10) == Some(HISTORY_VERSION.to_be_bytes().as_slice()),
        "invalid RGT file header"
    );
    let mut reader = StrictReader::in_memory::<MAX_PACKAGE>(&rgt[10..]);
    ensure!(rgt::parse_history(&mut reader)? == expected.contract_id, "unexpected RGT contract ID");
    let history = TransferHistory::<NoteSeal>::strict_decode(&mut reader)?;
    ensure!(reader.into_cursor().position() as usize == rgt.len() - 10, "trailing history data");
    // Unsigned articles are authenticated by the separately selected articles ID.
    // An issuer-signature scheme requires its own identity verifier.
    let articles = history.articles(|_, _, _| Err(()))?;
    ensure!(articles.articles_id() == expected, "RGT articles differ from requested contract");
    let meta = articles.contract_meta();
    ensure!(
        meta.testnet == (meta.consensus == rgt::Consensus::TondiTestnet),
        "inconsistent RGT network designation"
    );
    NativeContract::with(articles, history, dir.to_owned()).map_err(|e| anyhow::anyhow!("{e}"))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Extension {
    pub(crate) headers: Vec<Header>,
    votes: Vec<Attestation>,
    successor: Option<Committee>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    extensions: Vec<Extension>,
    bodies: Vec<ExecutedCommit>,
}

#[derive(Clone, Copy)]
pub struct Pin {
    pub index: u64,
    pub id: Hash32,
}

/// Independently supplied invoice terms. The outpoint identifies a particular delivery.
pub struct Delivery {
    pub point: OutPoint,
    pub auth: Hash32,
    pub allocation: crate::payment::Allocation,
}

pub(crate) fn check_delivery(contract: &NativeContract, delivery: &Delivery) -> Result<()> {
    let state = contract.state();
    let cells = state
        .owned
        .get(&delivery.allocation.state)
        .context("missing requested RGT state")?;
    let mut matching = cells.iter().filter(|c| {
        c.assignment.seal.point() == delivery.point
            && c.assignment.data == delivery.allocation.value
    });
    let cell = matching
        .next()
        .context("history does not deliver the requested RGT assignment")?;
    ensure!(matching.next().is_none(), "ambiguous RGT delivery");
    let record = contract
        .witnesses()
        .find(|w| {
            w.id.0 == delivery.point.transaction_id.as_bytes() && w.opids.contains(&cell.addr.opid)
        })
        .context("delivery requires a published transfer")?;
    let tx = record.published.transaction()?;
    ensure!(
        tx.outputs
            .get(delivery.point.index as usize)
            .is_some_and(|n| n.auth.script_hash == delivery.auth),
        "destination Note has the wrong Auth"
    );
    Ok(())
}

pub(crate) fn required_witnesses(
    contract: &NativeContract,
    genesis: &Genesis,
) -> Result<BTreeMap<NoteTxid, rgt::note::NoteWitness>> {
    let mut required = BTreeMap::new();
    for w in contract.witnesses() {
        let tx = w.published.transaction()?;
        ensure!(tx.network == genesis.network, "wrong Tondi network");
        required.insert(w.id, w.published);
    }
    for (_, op, rels) in contract.operations() {
        ensure!(rels.witness_ids.len() == 1, "each v10 operation needs one publication");
        let wid = rels.witness_ids.first().unwrap();
        let tx = required
            .get(wid)
            .context("missing publication")?
            .transaction()?;
        ensure!(!op.destructible_in.is_empty(), "transfer has no previous Note seal");
        for opening in rels.defines.values() {
            ensure!(
                opening.txid.is_none()
                    && tx.outputs.get(opening.vout as usize).is_some_and(|n| n
                        .auth
                        .script_hash
                        .as_bytes()
                        == opening.auth.to_byte_array()),
                "invalid successor Note"
            );
        }
    }
    ensure!(!required.is_empty(), "no RGT transfer witnesses");
    Ok(required)
}

fn verify_evidence(
    genesis: &Genesis,
    pin: Pin,
    contract: &NativeContract,
    evidence: &Evidence,
) -> Result<()> {
    verify_records(genesis, pin, required_witnesses(contract, genesis)?, evidence)
}

fn verify_records(
    genesis: &Genesis,
    pin: Pin,
    mut required: BTreeMap<NoteTxid, rgt::note::NoteWitness>,
    evidence: &Evidence,
) -> Result<()> {
    let chain = CheckpointChain::new(genesis.clone())?;
    let version = chain.commitment_version();
    let mut chain = chain.v10_reader();
    let mut headers = BTreeMap::new();
    let mut pinned = pin.index == 0 && pin.id == genesis.id();
    for extension in &evidence.extensions {
        chain.verify(&extension.headers, &extension.votes, extension.successor.clone())?;
        for h in &extension.headers {
            pinned |= h.commit_index == pin.index && h.id() == pin.id;
            headers.insert(h.commit_index, h);
        }
    }
    ensure!(pinned, "trusted checkpoint missing or mismatched");

    let mut seen = BTreeSet::new();
    for body in &evidence.bodies {
        let height = body.header.commit_index;
        ensure!(
            seen.insert(height) && headers.get(&height) == Some(&&body.header),
            "unauthenticated or duplicate checkpoint body"
        );
        ensure!(
            body.input_root() == body.header.input_root
                && body.execution_root_for(version)? == body.header.execution_root,
            "checkpoint body commitment mismatch"
        );
        body.validate_outcomes()?;
        let mut matched = false;
        for (record, outcome) in body.records.iter().zip(&body.outcomes) {
            let Outcome::Transaction(success) = outcome else {
                continue;
            };
            let txid = NoteTxid(success.transaction.as_bytes());
            if let Some(witness) = required.get(&txid) {
                ensure!(
                    witness.record() == tondi_consensus_core::granted_record::body(record)?,
                    "certified spend differs from RGT witness"
                );
                required.remove(&txid);
                matched = true;
            }
        }
        ensure!(matched, "checkpoint contains no required successful spend");
    }
    ensure!(required.is_empty(), "missing certified spend for RGT transfer");
    Ok(())
}

pub fn verify<'a>(
    bytes: &'a [u8],
    genesis: &Genesis,
    pin: Pin,
    expected: ArticlesId,
    delivery: &Delivery,
) -> Result<&'a [u8]> {
    let (rgt, evidence) = split(bytes)?;
    let dir = tempfile::tempdir()?;
    let contract = read_contract(rgt, dir.path(), expected)?;
    verify_evidence(genesis, pin, &contract, &evidence)?;
    check_delivery(&contract, delivery)?;
    Ok(rgt)
}

pub fn split(bytes: &[u8]) -> Result<(&[u8], Evidence)> {
    ensure!(
        bytes.len() <= MAX_PACKAGE && bytes.starts_with(MAGIC),
        "invalid v10 verification package"
    );
    let len = u32::from_le_bytes(
        bytes
            .get(8..12)
            .context("truncated RGT length")?
            .try_into()?,
    ) as usize;
    let (rgt, json) = bytes[12..]
        .split_at_checked(len)
        .context("truncated RGT history")?;
    let evidence: Evidence = serde_json::from_slice(json)?;
    Ok((rgt, evidence))
}

impl Evidence {
    pub fn for_spend(mut self, id: Hash32) -> Self {
        self.bodies.retain(|b| {
            b.outcomes
                .iter()
                .any(|o| matches!(o,Outcome::Transaction(t) if t.transaction == id))
        });
        self
    }

    pub fn verify_spend(
        &self,
        genesis: &Genesis,
        pin: Pin,
        witness: rgt::note::NoteWitness,
    ) -> Result<()> {
        let tx = witness.transaction()?;
        ensure!(tx.network == genesis.network, "terminal witness on wrong network");
        verify_records(
            genesis,
            pin,
            [(NoteTxid(tx.id().as_bytes()), witness)]
                .into_iter()
                .collect(),
            self,
        )
    }
}
pub(crate) fn get<T: serde::de::DeserializeOwned>(http: &Client, url: String) -> Result<T> {
    let response = http.get(url).send()?.error_for_status()?;
    Ok(serde_json::from_slice(&read_bounded(response, MAX_RESPONSE)?)?)
}

pub(crate) fn fetch_extension(
    http: &Client,
    rpc: &str,
    chain: &mut CheckpointExtensionReader,
    limit: u64,
) -> Result<Extension> {
    let extension: Option<Extension> = get(
        http,
        format!(
            "{rpc}/v1/checkpoint-proof?after={}&anchor={}&limit={limit}",
            chain.index(),
            chain.head()
        ),
    )?;
    let extension = extension.context("checkpoint extension unavailable")?;
    ensure!(extension.headers.len() <= limit as usize, "oversized checkpoint extension");
    chain.verify(&extension.headers, &extension.votes, extension.successor.clone())?;
    Ok(extension)
}

pub(crate) fn fetch_body(http: &Client, rpc: &str, header: &Header) -> Result<ExecutedCommit> {
    get(
        http,
        format!("{rpc}/v1/checkpoint-proof/{}/body?header={}", header.commit_index, header.id()),
    )
}

/// Collect the certified header prefix and only the checkpoint bodies needed by the transfer.
pub fn pack(
    rgt: &[u8],
    genesis: &Genesis,
    pin: Pin,
    expected: ArticlesId,
    rpc: &str,
) -> Result<Vec<u8>> {
    let dir = tempfile::tempdir()?;
    let contract = read_contract(rgt, dir.path(), expected)?;
    let required = required_witnesses(&contract, genesis)?;
    let evidence = collect(genesis, pin, required, rpc, 12 + rgt.len())?;
    let mut bytes = Vec::new();
    bytes.write_all(MAGIC)?;
    bytes.write_all(&u32::try_from(rgt.len())?.to_le_bytes())?;
    bytes.write_all(rgt)?;
    serde_json::to_writer(&mut bytes, &evidence)?;
    ensure!(bytes.len() <= MAX_PACKAGE, "proof package too large");
    Ok(bytes)
}

pub fn collect_spend(
    genesis: &Genesis,
    pin: Pin,
    witness: rgt::note::NoteWitness,
    rpc: &str,
) -> Result<Evidence> {
    let tx = witness.transaction()?;
    ensure!(tx.network == genesis.network, "terminal witness on wrong network");
    collect(
        genesis,
        pin,
        [(NoteTxid(tx.id().as_bytes()), witness)]
            .into_iter()
            .collect(),
        rpc,
        0,
    )
}
fn collect(
    genesis: &Genesis,
    pin: Pin,
    required: BTreeMap<NoteTxid, rgt::note::NoteWitness>,
    rpc: &str,
    base_size: usize,
) -> Result<Evidence> {
    let http = Client::builder().timeout(Duration::from_secs(15)).build()?;
    let rpc = rpc.trim_end_matches('/');
    #[derive(Deserialize)]
    struct ReceiptHint {
        header: Option<Header>,
    }
    let mut needed = BTreeSet::new();
    for w in required.values() {
        let tx = w.transaction()?;
        let hint: ReceiptHint =
            get(&http, format!("{rpc}/v1/receipts/{}?witness={}", tx.id(), tx.witness_id()))?;
        needed.insert(
            hint.header
                .context("exact witness not yet certified or unavailable")?
                .commit_index,
        );
    }
    let end = (*needed.last().context("no transfer receipts")?).max(pin.index);
    let mut evidence = Evidence { extensions: vec![], bodies: vec![] };
    let mut chain = CheckpointChain::new(genesis.clone())?.v10_reader();
    let mut size = base_size;
    while chain.index() < end {
        let limit = (end - chain.index()).min(CheckpointExtensionReader::MAX_HEADERS as u64);
        let extension = fetch_extension(&http, rpc, &mut chain, limit)?;
        size += serde_json::to_vec(&extension)?.len();
        ensure!(size <= MAX_PACKAGE, "proof package too large");
        for h in &extension.headers {
            if needed.contains(&h.commit_index) {
                let body = fetch_body(&http, rpc, h)?;
                size += serde_json::to_vec(&body)?.len();
                ensure!(size <= MAX_PACKAGE, "proof package too large");
                evidence.bodies.push(body);
            }
        }
        evidence.extensions.push(extension);
    }
    verify_records(genesis, pin, required, &evidence)?;
    Ok(evidence)
}
