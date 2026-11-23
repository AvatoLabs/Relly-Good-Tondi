//! Issue an isolated fixture and construct two signed, whole-allocation transfers.
//! Used by scripts/v10_transfer_local.py with a freshly generated local chain.
use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
};

use anyhow::{ensure, Context, Result};
use secp256k1::{Keypair, SECP256K1};
use std::io::Write;
use std::process::{Command, Stdio};
use tondi_consensus_core::genesis::Genesis;
use tondi_vm::{
    builder::{AuthDescriptor, DraftInput, NativeDraft},
    schnorr_auth,
    settlement::OrderingRecord,
    ClockContext, Note, OutPoint, ResolvedInput,
};

fn main() -> Result<()> {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--new-mnemonic")) {
        println!("{}", bip39::Mnemonic::from_entropy(&rand::random::<[u8; 32]>())?);
        return Ok(());
    }
    let dir = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .context("expected fresh output directory")?,
    );
    let genesis: Genesis = serde_json::from_slice(&fs::read(dir.join("genesis.json"))?)?;
    let mut seed = String::new();
    io::stdin().read_to_string(&mut seed)?;
    let rgt = PathBuf::from(
        std::env::args_os()
            .nth(2)
            .context("expected path to rgt binary")?,
    );
    let work = tempfile::tempdir()?;
    let file = |name: &str| work.path().join(name);
    let descriptor_file = PathBuf::from(
        std::env::args_os()
            .nth(3)
            .context("expected recipient descriptor")?,
    );
    let receiver: rgt_runtime::capsule::Receiver =
        serde_json::from_slice(&fs::read(&descriptor_file)?)?;
    let next = tondi_vm::Auth { script_hash: receiver.auth };
    let recovered = std::env::args_os().nth(4).map(PathBuf::from);
    let (hop, source, articles, input) = if let Some(snapshot) = &recovered {
        let wallet: serde_json::Value =
            serde_json::from_slice(&fs::read(snapshot.join("wallet.json"))?)?;
        let assets = wallet["assets"].as_array().context("snapshot assets")?;
        ensure!(assets.len() == 1, "expected one recovered allocation");
        let a = &assets[0];
        (
            2,
            snapshot.join(a["history"].as_str().context("history")?),
            a["articles"].as_str().context("articles")?.to_owned(),
            serde_json::from_value::<DraftInput>(a["draftInput"].clone())?,
        )
    } else {
        let key = Keypair::from_seckey_slice(SECP256K1, &hex::decode(seed.trim())?)?;
        let (auth, _) = schnorr_auth(key.x_only_public_key().0.serialize());
        let index = genesis
            .notes
            .iter()
            .position(|n| n.auth == auth && n.facets.is_empty())
            .context("local genesis funding Note")?;
        let point = OutPoint::new(genesis.id(), index.try_into()?);
        let note = genesis.notes[index].clone();
        ensure!(
            Command::new(&rgt)
                .args(["create-issuer", "--output"])
                .arg(file("demo.issuer"))
                .status()?
                .success(),
            "issuer creation failed"
        );
        let source = dir.join("issue.rgt");
        let result = Command::new(&rgt)
            .arg("issue")
            .arg(file("demo.issuer"))
            .args([
                "--outpoint",
                &format!("{}:{}", point.transaction_id, point.index),
                "--auth",
                &auth.script_hash.to_string(),
                "--amount",
                "100",
                "--testnet",
                "--output",
            ])
            .arg(&source)
            .output()?;
        ensure!(
            result.status.success(),
            "issue failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let articles = String::from_utf8(result.stdout)?.trim().to_string();
        let (_, script) = schnorr_auth(key.x_only_public_key().0.serialize());
        let input = DraftInput {
            outpoint: point,
            entry: ResolvedInput {
                note,
                birth_epoch: 0,
                birth_time_seconds: genesis.time_seconds,
                is_reward: false,
            },
            auth: Some(AuthDescriptor { script }),
            since: 0,
            consume: true,
        };
        (1, source, articles, input)
    };
    let source = std::env::args_os()
        .nth(5)
        .map(PathBuf::from)
        .unwrap_or(source);
    let hop = std::env::args()
        .nth(6)
        .map(|s| s.parse::<usize>())
        .transpose()?
        .unwrap_or(hop);
    let compact = fs::read(&source)?.starts_with(rgt_runtime::recursive::MAGIC);
    let point = input.outpoint;
    let value_flag = if hop == 1 { "--amount" } else { "--value" };
    let payment = file(&format!("hop-{hop}.json"));
    ensure!(
        Command::new(&rgt)
            .args([
                "invoice",
                "--articles",
                &articles,
                "--input",
                &format!("{}:{}", point.transaction_id, point.index),
                "--vout",
                "0",
                "--receiver",
                descriptor_file.to_str().context("descriptor path")?,
                value_flag,
                "100",
                "--output"
            ])
            .arg(&payment)
            .status()?
            .success(),
        "invoice failed"
    );
    let output_value = input
        .entry
        .note
        .value
        .checked_sub(1_000_000)
        .context("insufficient fixture funding")?;
    let draft = NativeDraft {
        network: genesis.network,
        inputs: vec![input],
        outputs: vec![Note::plain(output_value, next)],
        programs: vec![],
        state_creations: vec![],
        validation_scripts: vec![],
        payload: vec![],
    };
    fs::write(file("draft.json"), serde_json::to_vec(&draft)?)?;
    let invoke = |cmd: &str| {
        let mut cli = Command::new(&rgt);
        cli.arg(cmd).arg(&source).arg("--payment").arg(&payment);
        cli
    };
    let pstt_path = file(&format!("hop-{hop}.pstt"));
    ensure!(
        invoke("plan")
            .arg("--draft")
            .arg(file("draft.json"))
            .arg("--output")
            .arg(&pstt_path)
            .status()?
            .success(),
        "plan failed"
    );
    let signed = file("signed.pstt");
    let mut sign = Command::new(&rgt);
    sign.arg("sign")
        .arg(&pstt_path)
        .arg("--output")
        .arg(&signed);
    if recovered.is_some() {
        sign.arg("--seed-genesis").arg(dir.join("genesis.json"));
    }
    let mut signer = sign.stdin(Stdio::piped()).spawn()?;
    signer
        .stdin
        .take()
        .context("signer input")?
        .write_all(seed.trim().as_bytes())?;
    ensure!(signer.wait()?.success(), "sign failed");
    let clock = file("clock.json");
    fs::write(
        &clock,
        serde_json::to_vec(&ClockContext {
            epoch: 0,
            decision_index: 1,
            time_seconds: genesis.time_seconds,
        })?,
    )?;
    let envelope = dir.join(format!("hop-{hop}.hex"));
    ensure!(
        Command::new(&rgt)
            .arg("finalize")
            .arg(&signed)
            .arg("--clock")
            .arg(clock)
            .arg("--genesis")
            .arg(dir.join("genesis.json"))
            .arg("--output")
            .arg(&envelope)
            .status()?
            .success(),
        "finalize failed"
    );
    fs::remove_file(signed)?;
    let record = hex::decode(fs::read_to_string(&envelope)?)?;
    let OrderingRecord::Transaction(tx) = OrderingRecord::decode(&record)? else {
        anyhow::bail!("expected transaction")
    };

    let ext = if compact { "rgtstep" } else { "rgt" };
    let next_source = dir.join(format!("hop-{hop}.{ext}"));
    ensure!(
        invoke("export-history")
            .arg("--envelope")
            .arg(envelope)
            .arg("--output")
            .arg(&next_source)
            .status()?
            .success(),
        "history export failed"
    );
    let capsule_bytes = tx
        .checks
        .iter()
        .find(|c| c.data.starts_with(rgt_runtime::capsule::MAGIC))
        .context("missing capsule")?
        .data
        .len();
    let delivery = serde_json::json!({"articles": articles, "txid": tx.id(), "witness":tx.witness_id(), "outpoint":format!("{}:0",tx.id()),
            "auth":next.script_hash,"envelopeBytes":record.len(), "capsuleBytes":capsule_bytes});
    fs::write(dir.join(format!("delivery-{hop}.json")), serde_json::to_vec_pretty(&delivery)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rgt::{CallParams, CoreParams, NamedState, RgtSealDef};
    use rgt_runtime::issuer::whole_allocation;

    #[test]
    fn transfer_rule_preserves_the_issued_amount() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (mut contract, opening) = rgt_runtime::payment::issue(
            whole_allocation()?,
            OutPoint::new(1.into(), 0),
            2.into(),
            rgt_runtime::payment::Allocation { state: "amount".into(), value: 100u64.into() },
            true,
            dir.path(),
        )?;
        let addr = contract.state().owned["amount"][0].addr;
        let transfer = |amount: u64| CallParams {
            core: CoreParams {
                method: "transfer".into(),
                global: vec![],
                owned: vec![NamedState::new_unlocked("amount", opening.auth_token(), amount)],
            },
            using: [(addr, None)].into_iter().collect(),
            reading: Default::default(),
        };
        assert!(contract.call(transfer(101), Default::default()).is_err());
        contract.call(transfer(100), Default::default())?;
        Ok(())
    }
}
