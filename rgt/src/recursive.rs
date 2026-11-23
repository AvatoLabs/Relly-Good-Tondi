//! Carry a proven current cell across a transfer without disclosing its operation history.
use crate::{
    package::MAX_PACKAGE,
    payment::{Allocation, Payment},
};
use anyhow::{ensure, Context, Result};
use bincode::Options;
use rgt::{Articles, ArticlesId, CellAddr, Issue, OpBuilder, Operation, Semantics, StateCell};
use rgt_lineage::{encode, Frontier, Opening, Step, Transfer};
use risc0_zkvm::{Receipt, VerifierContext};
use serde::{Deserialize, Serialize};
use strict_encoding::{StrictDecode, StrictReader};
use tondi_vm::{builder::NativeDraft, codec, OutPoint, Transition};
use tondi_wallet_pstt::Pstt;

pub const MAGIC: &[u8; 8] = b"RGTSTA\0\x01";
pub const PENDING: &[u8; 8] = b"RGTSTP\0\x01";

pub fn image_id() -> Result<risc0_zkvm::sha::Digest> {
    use hex::FromHex;
    Ok(risc0_zkvm::sha::Digest::from_hex(include_str!("recursive-image-id").trim())?)
}

pub fn strict<T: StrictDecode>(bytes: &[u8]) -> Result<T> {
    ensure!(bytes.len() <= rgt_lineage::LIMIT, "oversized strict state");
    let mut r = StrictReader::in_memory::<{ rgt_lineage::LIMIT }>(bytes);
    let v = T::strict_decode(&mut r)?;
    ensure!(r.into_cursor().position() as usize == bytes.len(), "trailing strict state");
    Ok(v)
}

pub fn verify_receipt(receipt: &Receipt, f: &Frontier) -> Result<()> {
    let id = image_id()?;
    receipt.inner.succinct()?;
    receipt.verify_with_context(&VerifierContext::default().with_dev_mode(false), id)?;
    ensure!(
        receipt.journal.bytes == f.journal(id.as_words().try_into()?),
        "receipt differs from state"
    );
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    pub frontier: Frontier,
    pub issue: Vec<u8>,
    pub semantics: Vec<u8>,
}

pub fn frame<T: Serialize>(magic: &[u8; 8], prefix: &[u8], fields: &T) -> Result<Vec<u8>> {
    let mut out = magic.to_vec();
    out.extend_from_slice(&u32::try_from(prefix.len())?.to_le_bytes());
    out.extend_from_slice(prefix);
    serde_json::to_writer(&mut out, fields)?;
    ensure!(out.len() <= MAX_PACKAGE, "oversized RGT state");
    Ok(out)
}

pub fn unframe<'a>(magic: &[u8; 8], bytes: &'a [u8]) -> Result<(&'a [u8], &'a [u8])> {
    ensure!(bytes.len() <= MAX_PACKAGE && bytes.starts_with(magic), "invalid RGT frame");
    let n = u32::from_le_bytes(bytes.get(8..12).context("missing frame size")?.try_into()?);
    bytes[12..]
        .split_at_checked(n as usize)
        .context("truncated frame")
}

impl Snapshot {
    pub fn write(&self, receipt: &Receipt) -> Result<Vec<u8>> {
        frame(
            MAGIC,
            &bincode::options()
                .with_fixint_encoding()
                .serialize(receipt)?,
            self,
        )
    }
    pub fn read(bytes: &[u8]) -> Result<(Self, Receipt)> {
        let (seal, fields) = unframe(MAGIC, bytes)?;
        let receipt = bincode::options()
            .with_fixint_encoding()
            .with_limit(MAX_PACKAGE as u64)
            .deserialize(seal)?;
        let state: Self = serde_json::from_slice(fields)?;
        verify_receipt(&receipt, &state.frontier)?;
        Ok((state, receipt))
    }
    pub fn articles(&self, expected: ArticlesId) -> Result<Articles> {
        let a = Articles::with(
            strict::<Semantics>(&self.semantics)?,
            strict::<Issue>(&self.issue)?,
            None,
            |_, _, _| Err(()),
        )?;
        ensure!(
            a.articles_id() == expected
                && self.frontier.contract == expected.contract_id.to_byte_array(),
            "unexpected articles"
        );
        let m = a.contract_meta();
        ensure!(
            m.testnet == (m.consensus == rgt::Consensus::TondiTestnet),
            "inconsistent contract network"
        );
        Ok(a)
    }
    pub fn check_cell(&self, articles: &Articles, allocation: &Allocation) -> Result<()> {
        let cell: StateCell = strict(&self.frontier.cell)?;
        let data = articles.default_api().build_destructible(
            allocation.state.clone(),
            allocation.value.clone(),
            articles.types(),
        )?;
        ensure!(
            cell.lock.is_none() && cell.data == data && cell.auth == self.frontier.opening.token(),
            "wrong or locked RGT cell"
        );
        Ok(())
    }
    fn operation(&self, p: &Payment) -> Result<(Operation, Articles)> {
        let f = &self.frontier;
        ensure!(
            p.receiver.genesis.as_bytes() == f.genesis
                && p.receiver.network.as_bytes() == f.network,
            "wrong compact transfer chain"
        );
        ensure!(
            p.input == OutPoint::new(f.txid.into(), f.opening.vout),
            "wrong compact source Note"
        );
        let articles = self.articles(p.articles.parse()?)?;
        self.check_cell(&articles, &p.allocation)?;
        ensure!(
            articles.default_api().verifiers.contains_key("transfer"),
            "missing transfer method"
        );
        use rgt::RgtSealDef;
        let op = OpBuilder::new(articles.contract_id(), articles.call_id("transfer"))
            .destroy(CellAddr::new(f.opid.into(), 0))
            .add_owned(
                p.allocation.state.clone(),
                p.opening().auth_token(),
                p.allocation.value.clone(),
                None,
                articles.default_api(),
                articles.types(),
            )
            .finalize();
        Ok((op, articles))
    }
    pub fn prepare(bytes: &[u8], p: &Payment, mut draft: NativeDraft) -> Result<Pstt> {
        let (state, _) = Self::read(bytes)?;
        let (op, _) = state.operation(p)?;
        ensure!(
            draft.inputs.iter().filter(|i| i.consume).count() == 1
                && draft.inputs.iter().any(|i| i.consume
                    && i.outpoint == p.input
                    && i.entry.note.auth.script_hash.as_bytes() == state.frontier.opening.auth),
            "compact transfer requires its single source Note"
        );
        ensure!(
            draft.network == p.receiver.network
                && draft
                    .outputs
                    .get(p.vout as usize)
                    .is_some_and(|n| n.auth.script_hash == p.receiver.auth),
            "wrong compact destination"
        );
        ensure!(draft.payload.is_empty(), "draft payload already present");
        draft.payload = crate::capsule::encrypt(p, bytes)?;
        crate::payment::prepare(draft, op.opid().to_byte_array())
    }
    pub fn step(&self, p: &Payment, body: Vec<u8>) -> Result<Step> {
        let (op, articles) = self.operation(p)?;
        Ok(Step {
            genesis: self.frontier.genesis,
            network: self.frontier.network,
            issue: self.issue.clone(),
            libs: articles.codex_libs().map(encode).collect(),
            opening: Opening {
                txid: None,
                vout: p.vout,
                auth: p.receiver.auth.as_bytes(),
                blinding: p.blinding.as_bytes(),
            },
            transfer: Some(Transfer {
                previous: self.frontier.clone(),
                operation: encode(&op),
                body,
            }),
        })
    }
}

// The preceding receipt and the one publicly certified transaction suffice to fold a new receipt.
#[derive(Serialize, Deserialize)]
pub struct Pending {
    pub payment: Payment,
    pub body: String,
}
pub fn receive(prior: &[u8], payment: &Payment, tx: &Transition) -> Result<Vec<u8>> {
    let (state, _) = Snapshot::read(prior)?;
    let body = codec::encode(tx.body());
    let step = state.step(payment, body.clone())?;
    let next = std::panic::catch_unwind(|| rgt_lineage::advance(&step))
        .map_err(|_| anyhow::anyhow!("invalid compact transition"))?;
    ensure!(
        next.txid == tx.id().as_bytes() && next.opening.auth == payment.receiver.auth.as_bytes(),
        "compact successor mismatch"
    );
    frame(PENDING, prior, &Pending { payment: payment.clone(), body: hex::encode(body) })
}
