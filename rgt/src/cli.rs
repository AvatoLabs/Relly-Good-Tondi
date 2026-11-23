use crate::package::{self, Delivery, Pin, MAX_PACKAGE};
use crate::payment::{self, Allocation, Payment};
use anyhow::{Context, Result};
use clap::Subcommand;
use rgt::{ArticlesId, RgtSealDef};
use std::{
    fs::File,
    path::{Path, PathBuf},
    str::FromStr,
};
use tondi_consensus_core::genesis::Genesis;
use tondi_vm::settlement::OrderingRecord;
use tondi_vm::{builder::NativeDraft, Hash32, OutPoint};
use tondi_wallet_pstt::Pstt;

#[derive(Clone, Debug, Eq, PartialEq, clap::Args)]
pub struct AllocationArgs {
    /// Owned state name in the contract API.
    #[arg(long, default_value = "amount")]
    state: rgt::StateName,
    /// Numeric allocation.
    #[arg(long, required_unless_present = "value", conflicts_with = "value")]
    amount: Option<u64>,
    /// Strict value in JSON, for a schema-defined allocation.
    #[arg(long)]
    value: Option<String>,
}

impl AllocationArgs {
    fn allocation(&self) -> Result<Allocation> {
        let value = match self.amount {
            Some(n) => n.into(),
            None => {
                serde_json::from_str(self.value.as_deref().context("missing allocation value")?)?
            }
        };
        Ok(Allocation { state: self.state.clone(), value })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum Command {
    /// Derive a public receiving descriptor from a mnemonic or hex seed on stdin.
    Receiver {
        #[arg(long)]
        genesis: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Restore live RGT allocations from certified archive bodies using a seed on stdin.
    Recover {
        #[arg(long)]
        genesis: PathBuf,
        #[arg(long)]
        checkpoint: String,
        #[arg(long)]
        rpc: String,
        /// New directory for the verified wallet snapshot.
        #[arg(long)]
        output: PathBuf,
    },
    /// Write an issuer for a fungible allocation transferred in full.
    CreateIssuer {
        #[arg(long)]
        output: PathBuf,
    },
    /// Add a native PSTT signature using a hex secret key read from standard input.
    Sign {
        pstt: PathBuf,
        /// Derive the spending key from the wallet seed for this genesis.
        #[arg(long)]
        seed_genesis: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a signed PSTT and write a hex Telegraph envelope for the node.
    Finalize {
        pstt: PathBuf,
        #[arg(long)]
        genesis: PathBuf,
        /// Native ClockContext JSON for the target ledger decision.
        #[arg(long)]
        clock: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Issue a schema-defined allocation to an existing Tondi Note using an RGT issuer.
    Issue {
        issuer: PathBuf,
        #[arg(long)]
        outpoint: String,
        #[arg(long)]
        auth: Hash32,
        #[command(flatten)]
        allocation: AllocationArgs,
        #[arg(long)]
        testnet: bool,
        #[arg(long)]
        output: PathBuf,
    },
    /// Create a private payment request for a whole allocation and a specific successor Note.
    Invoice {
        #[arg(long)]
        articles: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        vout: u32,
        #[arg(long)]
        receiver: PathBuf,
        #[command(flatten)]
        allocation: AllocationArgs,
        #[arg(long)]
        output: PathBuf,
    },
    /// Submit a finalized envelope to the v10 node admission API.
    Submit {
        envelope: PathBuf,
        #[arg(long)]
        rpc: String,
    },
    /// Plan a whole allocation transfer from a locally held RGT history before signing.
    Plan {
        source: PathBuf,
        #[arg(long)]
        payment: PathBuf,
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Bind the planned transfer to an exact signed Telegraph envelope and export the receiver history.
    #[command(name = "export-history")]
    ExportHistory {
        source: PathBuf,
        #[arg(long)]
        payment: PathBuf,
        #[arg(long)]
        envelope: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Embed an RGT operation in an unsigned v10 NativeDraft and emit its signing PSTT.
    Prepare {
        draft: PathBuf,
        #[arg(long)]
        opid: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Collect authenticated HTTP checkpoint evidence for a strict RGT Note-seal history.
    Pack {
        history: PathBuf,
        #[arg(long)]
        genesis: PathBuf,
        #[arg(long)]
        articles: String,
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        checkpoint: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify the package offline against the receiver's chain anchor and requested allocation.
    Verify {
        package: PathBuf,
        #[arg(long)]
        genesis: PathBuf,
        #[arg(long)]
        articles: String,
        #[arg(long)]
        checkpoint: String,
        #[arg(long)]
        outpoint: String,
        #[arg(long)]
        auth: Hash32,
        #[command(flatten)]
        allocation: AllocationArgs,
        /// Export the verified history for a subsequent transfer.
        #[arg(long)]
        save_history: Option<PathBuf>,
    },
}

fn wallet_keys(genesis: &Genesis) -> Result<crate::capsule::WalletKeys> {
    let raw = zeroize::Zeroizing::new(package::read_bounded(std::io::stdin().lock(), 1024)?);
    crate::capsule::WalletKeys::derive(std::str::from_utf8(&raw)?.trim(), genesis)
}

fn pair(s: &str) -> Result<(&str, &str)> {
    s.split_once(':')
        .context("expected two fields separated by ':'")
}

fn chain(path: &Path, checkpoint: &str) -> Result<(Genesis, Pin)> {
    let (index, id) = pair(checkpoint)?;
    Ok((serde_json::from_slice(&load(path)?)?, Pin { index: index.parse()?, id: id.parse()? }))
}

fn load(path: &Path) -> Result<Vec<u8>> {
    package::read_bounded(File::open(path)?, MAX_PACKAGE)
}

pub(crate) fn save(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::new_in(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    f.write_all(data)?;
    f.persist_noclobber(path)?;
    Ok(())
}

impl Command {
    pub fn run(&self) -> Result<()> {
        match self {
            Self::Receiver { genesis, output } => {
                let genesis: Genesis = serde_json::from_slice(&load(genesis)?)?;
                save(
                    output,
                    &serde_json::to_vec_pretty(&wallet_keys(&genesis)?.receiver(&genesis))?,
                )?;
            }
            Self::Recover { genesis, checkpoint, rpc, output } => {
                let (genesis, pin) = chain(genesis, checkpoint)?;
                crate::recovery::restore(&genesis, pin, &wallet_keys(&genesis)?, rpc, output)?;
            }
            Self::CreateIssuer { output } => {
                let dir = tempfile::tempdir()?;
                let path = dir.path().join("whole.issuer");
                crate::issuer::whole_allocation()?.save(&path)?;
                save(output, &load(&path)?)?;
            }
            Self::Sign { pstt, output, seed_genesis } => {
                let mut pstt: Pstt = serde_json::from_slice(&load(pstt)?)?;
                let key = if let Some(file) = seed_genesis {
                    wallet_keys(&serde_json::from_slice(&load(file)?)?)?
                        .spend
                        .secret_bytes()
                } else {
                    let raw = zeroize::Zeroizing::new(package::read_bounded(
                        std::io::stdin().lock(),
                        128,
                    )?);
                    let mut bytes = [0; 32];
                    hex::decode_to_slice(std::str::from_utf8(&raw)?.trim(), &mut bytes)?;
                    bytes
                };
                anyhow::ensure!(pstt.sign(&[key])? > 0, "key did not sign a PSTT slot");
                save(output, &serde_json::to_vec(&pstt)?)?;
            }
            Self::Finalize { pstt, genesis, clock, output } => {
                let pstt: Pstt = serde_json::from_slice(&load(pstt)?)?;
                let genesis: Genesis = serde_json::from_slice(&load(genesis)?)?;
                let tx = pstt.extract(genesis.network, serde_json::from_slice(&load(clock)?)?)?;
                save(output, hex::encode(OrderingRecord::Transaction(tx).encode()).as_bytes())?;
            }
            Self::Issue { issuer, outpoint, auth, allocation, testnet, output } => {
                let issuer = rgt::Issuer::load(issuer, |_, _, _| Err(()))?;
                let (txid, vout) = pair(outpoint)?;
                let dir = tempfile::tempdir()?;
                let (contract, opening) = payment::issue(
                    issuer,
                    OutPoint::new(txid.parse()?, vout.parse()?),
                    *auth,
                    allocation.allocation()?,
                    *testnet,
                    dir.path(),
                )?;
                let file = dir.path().join("issue.rgt");
                contract.export_history_to_file(&file, [opening.auth_token()])?;
                save(output, &std::fs::read(file)?)?;
                println!("{}", contract.articles().articles_id());
            }
            Self::Invoice { articles, input, vout, receiver, allocation, output } => {
                let articles: ArticlesId = articles.parse()?;
                let (txid, index) = pair(input)?;
                let payment = Payment {
                    articles: articles.to_string(),
                    input: OutPoint::new(txid.parse()?, index.parse()?),
                    vout: *vout,
                    receiver: serde_json::from_slice(&load(receiver)?)?,
                    blinding: rand::random::<[u8; 32]>().into(),
                    allocation: allocation.allocation()?,
                };
                save(output, &serde_json::to_vec(&payment)?)?;
            }
            Self::Submit { envelope, rpc } => {
                let raw = hex::decode(std::str::from_utf8(&load(envelope)?)?.trim())?;
                let OrderingRecord::Transaction(tx) = OrderingRecord::decode(&raw)? else {
                    anyhow::bail!("expected a native transaction");
                };
                let url = format!("{}/v1/envelopes", rpc.trim_end_matches('/'));
                let http = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(15))
                    .build()?;
                let response = http
                    .post(url)
                    .json(&hex::encode(raw))
                    .send()?
                    .error_for_status()?;
                #[derive(serde::Deserialize)]
                struct Admission {
                    status: String,
                }
                let admission: Admission =
                    serde_json::from_slice(&package::read_bounded(response, 16_384)?)?;
                anyhow::ensure!(admission.status == "queued", "unexpected admission response");
                println!("Queued {} witness {}", tx.id(), tx.witness_id());
            }
            Self::Plan { source, payment, draft, output } => {
                let dir = tempfile::tempdir()?;
                let payment: Payment = serde_json::from_slice(&load(payment)?)?;
                let history = load(source)?;
                let draft = serde_json::from_slice(&load(draft)?)?;
                let pstt = if history.starts_with(crate::recursive::MAGIC) {
                    crate::recursive::Snapshot::prepare(&history, &payment, draft)?
                } else {
                    let mut contract =
                        package::read_contract(&history, dir.path(), payment.articles.parse()?)?;
                    payment.prepare(&mut contract, draft, &history)?
                };
                save(output, &serde_json::to_vec(&pstt)?)?;
            }
            Self::ExportHistory { source, payment, envelope, output } => {
                let dir = tempfile::tempdir()?;
                let payment: Payment = serde_json::from_slice(&load(payment)?)?;
                let source = load(source)?;
                let raw = hex::decode(std::str::from_utf8(&load(envelope)?)?.trim())?;
                let OrderingRecord::Transaction(tx) = OrderingRecord::decode(&raw)? else {
                    anyhow::bail!("expected a signed transaction envelope")
                };
                if source.starts_with(crate::recursive::MAGIC) {
                    return save(output, &crate::recursive::receive(&source, &payment, &tx)?);
                }
                let mut contract =
                    package::read_contract(&source, dir.path(), payment.articles.parse()?)?;
                let file = dir.path().join("next.rgt");
                payment.export_history(&mut contract, tx, &file)?;
                save(output, &std::fs::read(file)?)?;
            }
            Self::Prepare { draft, opid, output } => {
                let draft: NativeDraft = serde_json::from_slice(&load(draft)?)?;
                let op = rgt::Opid::from_str(opid)?;
                save(output, &serde_json::to_vec(&payment::prepare(draft, op.into())?)?)?;
            }
            Self::Pack { history, genesis, articles, rpc, checkpoint, output } => {
                let rgt = load(history)?;
                let (genesis, pin) = chain(genesis, checkpoint)?;
                let bytes =
                    package::pack(&rgt, &genesis, pin, articles.parse::<ArticlesId>()?, rpc)?;
                save(output, &bytes)?;
                println!(
                    "RGT history {} bytes, certified package {} bytes",
                    rgt.len(),
                    bytes.len()
                );
            }
            Self::Verify {
                package: file,
                genesis,
                articles,
                checkpoint,
                outpoint,
                auth,
                allocation,
                save_history,
            } => {
                let bytes = load(file)?;
                let (genesis, pin) = chain(genesis, checkpoint)?;
                let (txid, index) = pair(outpoint)?;
                let delivery = Delivery {
                    point: OutPoint::new(txid.parse()?, index.parse()?),
                    auth: *auth,
                    allocation: allocation.allocation()?,
                };
                let history = package::verify(
                    &bytes,
                    &genesis,
                    pin,
                    articles.parse::<ArticlesId>()?,
                    &delivery,
                )?;
                if let Some(path) = save_history {
                    save(path, history)?;
                }
                println!(
                    "Verified delivery of {} {} to {outpoint} ({} bytes)",
                    delivery.allocation.value,
                    delivery.allocation.state,
                    bytes.len()
                );
            }
        }
        Ok(())
    }
}
