//! Keep independently verifiable segment receipts when a local wallet fold is interrupted.
use anyhow::{ensure, Context, Result};
use bincode::Options;
use risc0_zkvm::{
    sha::{Digest, Digestible, Impl, Sha256},
    ApiClient, Asset, AssetRequest, Assumption, ExecutorEnv, InnerReceipt, MaybePruned, Output, ProverOpts, Receipt,
    ReceiptClaim, SuccinctReceipt, VerifierContext,
};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path};

#[derive(Serialize, Deserialize)]
struct Execution {
    segments: usize,
    cycles: u64,
    claim: ReceiptClaim,
    journal: Vec<u8>,
}

/// Join receipts from one exact execution, including after a process or machine restart.
fn record_execution(cache: &Path, client: &ApiClient, binary: &[u8], env: &ExecutorEnv<'_>) -> Result<Execution> {
    let ready = cache.join("execution");
    if !ready.is_dir() {
        let mut temp = tempfile::Builder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temp.permissions(fs::Permissions::from_mode(0o700));
        }
        let staging = temp.tempdir_in(cache)?;
        let mut count = 0;
        let session = client.execute(
            env,
            Asset::Inline(binary.to_vec().into()),
            AssetRequest::Path(staging.path().to_owned()),
            |_, asset| {
                let Asset::Path(source) = asset else { anyhow::bail!("expected a local segment trace") };
                let path = staging.path().join(format!("part-{count}"));
                fs::rename(source, &path)?;
                fs::File::open(path)?.sync_all()?;
                count += 1;
                Ok(())
            },
        )?;
        ensure!(count == session.segments.len() && count > 0, "incomplete guest execution");
        let execution = Execution {
            segments: count,
            cycles: session.cycles(),
            claim: session.receipt_claim.context("missing executed claim")?,
            journal: session.journal.bytes,
        };
        let mut manifest = fs::File::create(staging.path().join("session.json"))?;
        serde_json::to_writer(&mut manifest, &execution)?;
        manifest.sync_all()?;
        #[cfg(unix)]
        fs::File::open(staging.path())?.sync_all()?;
        if let Err(error) = fs::rename(staging.path(), &ready) {
            if !ready.is_dir() {
                return Err(error.into());
            }
        }
        #[cfg(unix)]
        fs::File::open(cache)?.sync_all()?;
    }
    Ok(serde_json::from_slice(&super::read(&ready.join("session.json"))?)?)
}

pub fn prove(
    directory: &Path,
    prover: &Path,
    binary: &[u8],
    env: &ExecutorEnv<'_>,
    witness: &[u8],
    previous: Option<Receipt>,
) -> Result<Receipt> {
    let key = format!("{}-{}", super::image_id()?, Impl::hash_bytes(witness));
    let cache = directory.join(key);
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.recursive(true).create(&cache)?;
    let client = ApiClient::new_sub_process(prover)?;
    let session = record_execution(&cache, &client, binary, env)?;
    let execution = cache.join("execution");
    let ctx = VerifierContext::default().with_dev_mode(false);
    let opts = ProverOpts::succinct();
    let count = session.segments;
    eprintln!("Executing {} user cycles in {count} proof segments", session.cycles);
    // The final segment commits to the predecessor assumption before resolve discharges it.
    let assumptions = match &previous {
        Some(prior) => vec![Assumption { claim: prior.claim()?.digest(), control_root: Digest::ZERO }],
        None => vec![],
    };
    let output: MaybePruned<Option<Output>> =
        Some(Output { journal: session.journal.clone().into(), assumptions: assumptions.into() }).into();
    let mut prefix: Option<SuccinctReceipt<ReceiptClaim>> = None;
    for index in 0..count {
        let file = execution.join(format!("prefix-{}.bin", index + 1));
        let cached = match fs::File::open(&file) {
            Ok(f) => bincode::options()
                .with_fixint_encoding()
                .with_limit(8 << 20)
                .deserialize_from::<_, SuccinctReceipt<ReceiptClaim>>(f)
                .ok()
                .filter(|receipt| receipt.verify_integrity_with_context(&ctx).is_ok()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        prefix = Some(match cached {
            Some(receipt) => {
                eprintln!("Reused saved proof prefix {}", index + 1);
                receipt
            }
            None => {
                let input = Asset::Path(execution.join(format!("part-{index}")));
                let mut segment = client.prove_segment(&opts, input, AssetRequest::Inline)?;
                if index + 1 == count {
                    ensure!(segment.claim.output.digest() == output.digest(), "wrong final segment output");
                    segment.claim.output = output.clone();
                }
                let lifted = client.lift(&opts, segment.try_into()?, AssetRequest::Inline)?;
                let receipt = match prefix {
                    Some(prior) => client.join(&opts, prior.try_into()?, lifted.try_into()?, AssetRequest::Inline)?,
                    None => lifted,
                };
                receipt.verify_integrity_with_context(&ctx)?;
                let mut tmp = tempfile::NamedTempFile::new_in(&execution)?;
                bincode::serialize_into(tmp.as_file_mut(), &receipt)?;
                tmp.flush()?;
                tmp.as_file().sync_all()?;
                tmp.persist(&file)?;
                #[cfg(unix)]
                fs::File::open(&execution)?.sync_all()?;
                receipt
            }
        });
        eprintln!("Verified segment {}/{count}", index + 1);
    }
    let mut succinct = prefix.context("empty proof execution")?;
    if let Some(prev) = previous {
        let assumption = prev.inner.succinct()?.clone();
        succinct = client.resolve(&opts, succinct.try_into()?, assumption.try_into()?, AssetRequest::Inline)?;
    }
    let receipt = Receipt::new(InnerReceipt::Succinct(succinct), session.journal);
    receipt.verify_with_context(&ctx, super::image_id()?)?;
    ensure!(receipt.claim()?.digest() == session.claim.digest(), "resolved receipt differs from execution");
    Ok(receipt)
}
