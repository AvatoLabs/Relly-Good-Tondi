//! Local succinct receipts for a single RGT allocation, plus certified terminal spend evidence.
mod work;

use anyhow::{ensure, Context, Result};
use bincode::Options;
use clap::{Args, Parser, Subcommand};
use rgt::{
    note::{NoteWitness, Opening as NoteOpening},
    Articles, ArticlesId, Issue, Semantics, StateCell,
};
use rgt_lineage::{encode, Frontier, Opening, Step, Transfer};
use rgt_runtime::package::{self, Evidence, Pin, MAX_PACKAGE};
use rgt_runtime::recursive::{self, image_id, strict, verify_receipt, Pending, Snapshot};
use risc0_zkvm::{ExecutorEnv, ExternalProver, Prover, ProverOpts, Receipt};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};
use tondi_consensus_core::genesis::Genesis;
use tondi_vm::{codec, settlement::OrderingRecord, Hash32, OutPoint};

const MAGIC: &[u8; 8] = b"RGTZKP\0\x01";
#[derive(Parser)]
#[command(about = "RGT recursive single-allocation proofs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Args)]
struct Chain {
    #[arg(long)]
    genesis: PathBuf,
    #[arg(long)]
    checkpoint: String,
    #[arg(long)]
    articles: ArticlesIdArg,
}
#[derive(Clone)]
struct ArticlesIdArg(ArticlesId);
impl std::str::FromStr for ArticlesIdArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        s.parse().map(Self).map_err(|e| format!("{e}"))
    }
}
#[derive(Subcommand)]
enum Command {
    /// Compute the image ID from an independently built guest executable.
    Image { program: PathBuf },
    /// Prove a delivery locally. A prior compact receipt allows resuming at its successor.
    Prove {
        package: PathBuf,
        #[command(flatten)]
        chain: Chain,
        #[arg(long)]
        program: PathBuf,
        #[arg(long, default_value = "r0vm")]
        prover: PathBuf,
        #[arg(long)]
        previous: Option<PathBuf>,
        /// Private directory for resuming individual proof segments after interruption.
        #[arg(long)]
        work_dir: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Certify a proven compact state using the exact signed terminal envelope and an archive.
    Certify {
        state: PathBuf,
        #[command(flatten)]
        chain: Chain,
        #[arg(long)]
        envelope: PathBuf,
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Fold a recovered compact transfer into a spendable compact state on this machine.
    Fold {
        step: PathBuf,
        /// Private directory for resuming individual proof segments after interruption.
        #[arg(long)]
        work_dir: Option<PathBuf>,
        #[arg(long)]
        program: PathBuf,
        #[arg(long, default_value = "r0vm")]
        prover: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify the succinct receipt, invoice terms and terminal publication offline.
    Verify {
        proof: PathBuf,
        #[command(flatten)]
        chain: Chain,
        #[arg(long)]
        outpoint: String,
        #[arg(long)]
        auth: Hash32,
        #[arg(long, default_value = "amount")]
        state: rgt::StateName,
        #[arg(long, required_unless_present = "value", conflicts_with = "value")]
        amount: Option<u64>,
        #[arg(long)]
        value: Option<String>,
        /// Save the proven cell, issuing terms and receipt for a compact transfer.
        #[arg(long)]
        save_state: Option<PathBuf>,
    },
}
#[derive(Serialize, Deserialize)]
struct Metadata {
    frontier: Frontier,
    issue: Vec<u8>,
    semantics: Vec<u8>,
    envelope: Vec<u8>,
    evidence: Evidence,
}
fn read(path: &Path) -> Result<Vec<u8>> {
    package::read_bounded(File::open(path)?, MAX_PACKAGE)
}
fn chain(args: &Chain) -> Result<(Genesis, Pin)> {
    let (height, hash) = args.checkpoint.split_once(':').context("expected INDEX:HEADER")?;
    Ok((serde_json::from_slice(&read(&args.genesis)?)?, Pin { index: height.parse()?, id: hash.parse()? }))
}
fn parts(proof: &[u8]) -> Result<(Receipt, Metadata)> {
    ensure!(proof.starts_with(MAGIC), "invalid RGT recursive proof");
    let size = u32::from_le_bytes(proof.get(8..12).context("truncated proof")?.try_into()?) as usize;
    let (seal, data) = proof[12..].split_at_checked(size).context("truncated receipt")?;
    Ok((bincode::options().with_limit(MAX_PACKAGE as u64).deserialize(seal)?, serde_json::from_slice(data)?))
}
fn opening(o: &NoteOpening) -> Opening {
    Opening {
        txid: o.txid.map(|x| x.0),
        vout: o.vout,
        auth: o.auth.to_byte_array(),
        blinding: o.blinding.to_byte_array(),
    }
}
fn compact_verify(
    meta: &Metadata,
    receipt: &Receipt,
    genesis: &Genesis,
    pin: Pin,
    expected: ArticlesId,
) -> Result<Articles> {
    let f = &meta.frontier;
    ensure!(
        f.genesis == genesis.id().as_bytes()
            && f.network == genesis.network.as_bytes()
            && f.contract == expected.contract_id.to_byte_array()
            && f.opening.txid.is_none(),
        "wrong RGT delivery context"
    );
    verify_receipt(receipt, f)?;
    let articles =
        Articles::with(strict::<Semantics>(&meta.semantics)?, strict::<Issue>(&meta.issue)?, None, |_, _, _| Err(()))?;
    ensure!(articles.articles_id() == expected, "unexpected articles");
    let OrderingRecord::Transaction(tx) = OrderingRecord::decode(&meta.envelope)? else {
        anyhow::bail!("invalid terminal envelope")
    };
    ensure!(
        tx.id().as_bytes() == f.txid
            && tx.outputs.get(f.opening.vout as usize).is_some_and(|n| n.auth.script_hash.as_bytes() == f.opening.auth),
        "terminal Note differs from receipt"
    );
    meta.evidence.verify_spend(genesis, pin, NoteWitness::new(tx)?)?;
    Ok(articles)
}
fn local_prover<'a>(
    program: &Path,
    prover: &'a Path,
    work_dir: Option<&'a Path>,
) -> Result<impl Fn(&Step, Option<Receipt>) -> Result<(Frontier, Receipt)> + 'a> {
    let elf = read(program)?;
    let binary = risc0_binfmt::ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF);
    let id = image_id()?;
    ensure!(binary.compute_image_id()? == id, "guest program differs from pinned image");
    let binary = binary.encode();
    let image: [u32; 8] = id.as_words().try_into()?;
    let engine = ExternalProver::new("RGT local prover", prover.to_path_buf());
    let prove = move |input: &Step, previous: Option<Receipt>| -> Result<(Frontier, Receipt)> {
        let f = std::panic::catch_unwind(|| rgt_lineage::advance(input))
            .map_err(|_| anyhow::anyhow!("outside the recursive single-cell profile"))?;
        let mut env = ExecutorEnv::builder();
        let bytes = serde_json::to_vec(input)?;
        env.write(&image)?.write(&u32::try_from(bytes.len())?)?.write_slice(&bytes);
        if let Some(prev) = &previous {
            env.add_assumption(prev.clone());
        }
        let started = std::time::Instant::now();
        let env = env.build()?;
        let receipt = if let Some(path) = work_dir {
            work::prove(path, prover, &binary, &env, &bytes, previous)?
        } else {
            let result = engine.prove_with_opts(env, &binary, &ProverOpts::succinct())?;
            eprintln!("Proved {} cycles across {} segments", result.stats.total_cycles, result.stats.segments);
            result.receipt
        };
        eprintln!("Local proof finished in {:.1}s", started.elapsed().as_secs_f64());
        verify_receipt(&receipt, &f)?;
        Ok((f, receipt))
    };
    Ok(prove)
}
fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp =
        tempfile::NamedTempFile::new_in(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?;
    tmp.write_all(bytes)?;
    tmp.persist_noclobber(path)?;
    Ok(())
}
fn save_delivery(output: &Path, receipt: &Receipt, meta: &Metadata) -> Result<()> {
    let seal = bincode::options().serialize(receipt)?;
    let bytes = recursive::frame(MAGIC, &seal, meta)?;
    save(output, &bytes)?;
    println!("Succinct receipt {} bytes, certified RGT proof {} bytes", seal.len(), bytes.len());
    Ok(())
}
fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Image { program } => {
            let elf = read(&program)?;
            println!(
                "{}",
                risc0_binfmt::ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF).compute_image_id()?
            );
        }
        Command::Certify { state, chain: args, envelope, rpc, output } => {
            let (genesis, pin) = chain(&args)?;
            let (state, receipt) = Snapshot::read(&read(&state)?)?;
            state.articles(args.articles.0)?;
            let raw = hex::decode(std::str::from_utf8(&read(&envelope)?)?.trim())?;
            let OrderingRecord::Transaction(tx) = OrderingRecord::decode(&raw)? else {
                anyhow::bail!("invalid terminal envelope")
            };
            ensure!(tx.id().as_bytes() == state.frontier.txid, "wrong terminal envelope");
            let evidence = package::collect_spend(&genesis, pin, NoteWitness::new(tx)?, &rpc)?;
            let meta = Metadata {
                frontier: state.frontier,
                issue: state.issue,
                semantics: state.semantics,
                envelope: raw,
                evidence,
            };
            compact_verify(&meta, &receipt, &genesis, pin, args.articles.0)?;
            save_delivery(&output, &receipt, &meta)?;
        }
        Command::Fold { step, program, prover, work_dir, output } => {
            let bytes = read(&step)?;
            let (prior, fields) = recursive::unframe(recursive::PENDING, &bytes)?;
            let pending: Pending = serde_json::from_slice(fields)?;
            let (mut state, receipt) = Snapshot::read(prior)?;
            let step = state.step(&pending.payment, hex::decode(pending.body)?)?;
            let (f, receipt) = local_prover(&program, &prover, work_dir.as_deref())?(&step, Some(receipt))?;
            state.frontier = f;
            save(&output, &state.write(&receipt)?)?;
        }
        Command::Verify { proof, chain: args, outpoint, auth, state, amount, value, save_state } => {
            let (genesis, pin) = chain(&args)?;
            let (receipt, meta) = parts(&read(&proof)?)?;
            let articles = compact_verify(&meta, &receipt, &genesis, pin, args.articles.0)?;
            let (tx, i) = outpoint.split_once(':').context("expected TXID:VOUT")?;
            let point = OutPoint::new(tx.parse()?, i.parse()?);
            let f = &meta.frontier;
            ensure!(
                point.transaction_id.as_bytes() == f.txid
                    && point.index == f.opening.vout
                    && auth.as_bytes() == f.opening.auth,
                "wrong destination"
            );
            let value = match amount {
                Some(n) => n.into(),
                None => serde_json::from_str(value.as_deref().context("missing state value")?)?,
            };
            let cell: StateCell = strict(&f.cell)?;
            ensure!(
                cell.lock.is_none()
                    && cell.data == articles.default_api().build_destructible(state, value, articles.types())?,
                "wrong or locked allocation"
            );
            if let Some(path) = save_state {
                let snapshot = Snapshot { frontier: meta.frontier, issue: meta.issue, semantics: meta.semantics };
                save(&path, &snapshot.write(&receipt)?)?;
            }
            println!("Verified recursive RGT delivery to {outpoint}");
        }
        Command::Prove { package: file, chain: args, program, prover, previous, work_dir, output } => {
            let (genesis, pin) = chain(&args)?;
            let raw = read(&file)?;
            let (history, evidence) = package::split(&raw)?;
            let dir = tempfile::tempdir()?;
            let contract = package::read_contract(history, dir.path(), args.articles.0)?;
            let articles = contract.articles();
            let mut input = Step {
                genesis: genesis.id().as_bytes(),
                network: genesis.network.as_bytes(),
                issue: encode(articles.issue()),
                libs: articles.codex_libs().map(encode).collect(),
                opening: opening(
                    contract.op_seals(articles.genesis_opid(), 1).defines.get(&0).context("missing genesis opening")?,
                ),
                transfer: None,
            };
            let prove = local_prover(&program, &prover, work_dir.as_deref())?;
            let (mut f, mut receipt) = if let Some(path) = previous {
                let (r, m) = parts(&read(&path)?)?;
                verify_receipt(&r, &m.frontier)?;
                ensure!(
                    m.frontier.genesis == input.genesis
                        && m.frontier.network == input.network
                        && m.frontier.contract == args.articles.0.contract_id.to_byte_array(),
                    "wrong predecessor context"
                );
                (m.frontier, r)
            } else {
                prove(&input, None)?
            };
            let witnesses =
                contract.witnesses().map(|w| (w.id, w.published)).collect::<std::collections::BTreeMap<_, _>>();
            let mut terminal = None;
            // The persistence backend may enumerate operations in a different order.
            let mut successors = std::collections::BTreeMap::new();
            for (opid, op, rels) in contract.operations() {
                if opid == articles.genesis_opid() {
                    continue;
                }
                ensure!(op.destructible_in.len() == 1, "expected exactly one source cell");
                let parent = op.destructible_in[0].addr.opid.to_byte_array();
                ensure!(successors.insert(parent, (opid, op, rels)).is_none(), "branched single-cell history");
            }
            while let Some((opid, op, rels)) = successors.remove(&f.opid) {
                ensure!(rels.witness_ids.len() == 1, "ambiguous witness");
                let witness = witnesses.get(rels.witness_ids.first().unwrap()).context("missing witness")?;
                let tx = witness.transaction()?;
                input.transfer = Some(Transfer { previous: f, operation: encode(&op), body: codec::encode(tx.body()) });
                input.opening = opening(rels.defines.get(&0).context("missing successor opening")?);
                (f, receipt) = prove(&input, Some(receipt))?;
                ensure!(
                    f.opid == opid.to_byte_array() && f.txid == tx.id().as_bytes(),
                    "native and guest transitions differ"
                );
                terminal = Some(witness);
            }
            let w = terminal.context("no successor transfer was proven")?;
            let meta = Metadata {
                evidence: evidence.for_spend(f.txid.into()),
                frontier: f,
                issue: input.issue,
                semantics: encode(articles.semantics()),
                envelope: w.record().to_owned(),
            };
            compact_verify(&meta, &receipt, &genesis, pin, args.articles.0)?;
            save_delivery(&output, &receipt, &meta)?;
        }
    }
    Ok(())
}
fn main() -> Result<()> {
    run()
}
