//! Wallet operations for moving one complete numeric RGT allocation to a successor Note.
use amplify::confinement::Confined;
use anyhow::{ensure, Context, Result};
use rgt::StateName;
use rgt::{
    Assignment, CallParams, CoreParams, CreateParams, Issuer, NamedState, Opid, RgtSealDef,
    SealWitness,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};
use strict_types::StrictVal;
use tondi_vm::{builder::NativeDraft, Hash32, OutPoint, Transition};
use tondi_wallet_pstt::Pstt;

use crate::package::NativeContract;
use rgt::note::{anchor, NoteSeal, NoteWitness, Opening};

/// Anchor an operation and produce the native signing container.
pub fn prepare(mut draft: NativeDraft, opid: [u8; 32]) -> Result<Pstt> {
    anchor(&mut draft.outputs, opid)?;
    Ok(draft.prepare()?.into())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Allocation {
    pub state: StateName,
    pub value: StrictVal,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Payment {
    pub articles: String,
    pub input: OutPoint,
    pub vout: u32,
    pub receiver: crate::capsule::Receiver,
    pub blinding: Hash32,
    pub allocation: Allocation,
}

impl Payment {
    pub fn opening(&self) -> Opening {
        Opening {
            txid: None,
            vout: self.vout,
            auth: self.receiver.auth.as_bytes().into(),
            blinding: self.blinding.as_bytes().into(),
        }
    }

    // CLI commands evaluate in a fresh temporary contract. Neither planning nor a
    // failed finalization mutates the wallet's source history.
    fn operation(
        &self,
        contract: &mut NativeContract,
        consumed: BTreeSet<OutPoint>,
    ) -> Result<Opid> {
        ensure!(consumed.contains(&self.input), "transfer must consume source Note");
        let state = contract.state();
        let mut matches = state
            .owned
            .get(&self.allocation.state)
            .context("missing requested owned state")?
            .iter()
            .filter(|cell| cell.assignment.seal.point() == self.input);
        let cell = matches.next().context("no allocation at source outpoint")?;
        ensure!(
            matches.next().is_none() && cell.assignment.data == self.allocation.value,
            "expected one whole source allocation"
        );
        ensure!(
            state.owned.values().flatten().all(|other| {
                other.addr == cell.addr || !consumed.contains(&other.assignment.seal.point())
            }),
            "native inputs would close another known RGT allocation"
        );
        let articles = contract.articles();
        ensure!(
            articles.default_api().verifiers.contains_key("transfer"),
            "missing transfer method"
        );
        articles.default_api().build_destructible(
            self.allocation.state.clone(),
            self.allocation.value.clone(),
            articles.types(),
        )?;
        let opening = self.opening();
        let params = CallParams {
            core: CoreParams {
                method: "transfer".into(),
                global: vec![],
                owned: vec![NamedState::new_unlocked(
                    self.allocation.state.clone(),
                    opening.auth_token(),
                    self.allocation.value.clone(),
                )],
            },
            using: [(cell.addr, None)].into_iter().collect(),
            reading: Default::default(),
        };
        Ok(contract
            .call(params, Confined::try_from_iter([(0, opening)])?)?
            .opid())
    }

    pub(crate) fn prepare(
        &self,
        contract: &mut NativeContract,
        mut draft: NativeDraft,
        history: &[u8],
    ) -> Result<Pstt> {
        let consumed = draft
            .inputs
            .iter()
            .filter(|i| i.consume)
            .map(|i| i.outpoint)
            .collect();
        ensure!(
            draft
                .outputs
                .get(self.vout as usize)
                .is_some_and(|o| o.auth.script_hash == self.receiver.auth),
            "draft recipient Auth mismatch"
        );
        ensure!(draft.network == self.receiver.network, "receiver network mismatch");
        ensure!(draft.payload.is_empty(), "RGT capsule requires an empty draft payload");
        draft.payload = crate::capsule::encrypt(self, history)?;
        prepare(draft, self.operation(contract, consumed)?.into())
    }

    pub(crate) fn export_history(
        &self,
        contract: &mut NativeContract,
        tx: Transition,
        path: &Path,
    ) -> Result<()> {
        ensure!(
            tx.outputs
                .get(self.vout as usize)
                .is_some_and(|o| o.auth.script_hash == self.receiver.auth),
            "published recipient Auth mismatch"
        );
        let consumed = tx
            .inputs
            .iter()
            .filter(|i| i.consumes())
            .map(|i| i.outpoint())
            .collect();
        let op = self.operation(contract, consumed)?;
        let witness = SealWitness::<NoteSeal>::new(NoteWitness::new(tx)?, Default::default());
        let source = NoteSeal {
            txid: self.input.transaction_id.as_bytes().into(),
            vout: self.input.index,
        };
        witness.verify_seal_closing(source, op.into())?;
        contract.include(op, witness.client, &witness.published);
        contract.export_history_to_file(path, [self.opening().auth_token()])?;
        Ok(())
    }
}

pub fn issue(
    issuer: Issuer,
    point: OutPoint,
    auth: Hash32,
    allocation: Allocation,
    testnet: bool,
    dir: &Path,
) -> Result<(NativeContract, Opening)> {
    ensure!(
        issuer.default_api().owned.contains_key(&allocation.state)
            && issuer.default_api().verifiers.contains_key("issue"),
        "issuer requires the requested owned state and issue method"
    );
    issuer.default_api().build_destructible(
        allocation.state.clone(),
        allocation.value.clone(),
        issuer.types(),
    )?;
    let opening = Opening {
        txid: Some(point.transaction_id.as_bytes().into()),
        vout: point.index,
        auth: auth.as_bytes().into(),
        blinding: rand::random::<[u8; 32]>().into(),
    };
    let mut params = if testnet {
        CreateParams::new_testnet(issuer.codex_id(), "NoteTransfer")
    } else {
        CreateParams::new_mainnet(issuer.codex_id(), "NoteTransfer")
    };
    params.push_owned_unlocked(
        allocation.state,
        Assignment::new_internal(opening.clone(), allocation.value),
    );
    Ok((NativeContract::issue(issuer, params, |_| Ok(dir.to_owned()))?, opening))
}
