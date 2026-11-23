use std::path::Path;

use rgt::{
    note::{anchor, NoteSeal, NoteTxid, NoteWitness, Opening},
    Assignment, CallParams, Contract, CoreParams, CreateParams, Issuer, NamedState, RgtSealDef,
    SealWitness,
};
use rgt_persist_fs::{PileFs, StockFs};
use tondi_vm::{
    builder::{AuthDescriptor, DraftInput, NativeDraft},
    schnorr_auth, Note, OutPoint, ResolvedInput,
};

pub fn setup(dir: &Path) -> (Contract<StockFs, PileFs<NoteSeal>>, Vec<NoteTxid>) {
    let issuer = Issuer::load("tests/data/Test.issuer", |_, _, _| Err(())).unwrap();
    let (auth, script) = schnorr_auth([7; 32]);
    let mut point = OutPoint::new(1.into(), 0);
    let mut note = Note::plain(20_000_000, auth);
    let genesis = Opening {
        txid: Some(NoteTxid(point.transaction_id.as_bytes())),
        vout: 0,
        auth: auth.script_hash.as_bytes().into(),
        blinding: [0; 32].into(),
    };
    let mut params = CreateParams::new_testnet(issuer.codex_id(), "NoteTransfer");
    params.push_owned_unlocked("amount", Assignment::new_internal(genesis, 100u64));
    let mut contract =
        Contract::<StockFs, PileFs<NoteSeal>>::issue(issuer, params, |_| Ok(dir.to_owned()))
            .unwrap();
    let mut ids = Vec::new();
    for i in 1..=3 {
        let opening = Opening {
            txid: None,
            vout: 0,
            auth: auth.script_hash.as_bytes().into(),
            blinding: [i; 32].into(),
        };
        let addr = contract.state().owned["amount"][0].addr;
        let call = CallParams {
            core: CoreParams {
                method: "transfer".into(),
                global: vec![],
                owned: vec![NamedState::new_unlocked("amount", opening.auth_token(), 100u64)],
            },
            using: [(addr, None)].into_iter().collect(),
            reading: Default::default(),
        };
        let opid = contract
            .call(call, amplify::confinement::Confined::try_from_iter([(0, opening)]).unwrap())
            .unwrap()
            .opid();
        let mut outputs = vec![Note::plain(note.value - 1_000_000, auth)];
        anchor(&mut outputs, opid.into()).unwrap();
        let draft = NativeDraft {
            network: 1.into(),
            inputs: vec![DraftInput {
                outpoint: point,
                entry: ResolvedInput {
                    note,
                    birth_epoch: 0,
                    birth_time_seconds: 0,
                    is_reward: false,
                },
                auth: Some(AuthDescriptor { script: script.clone() }),
                since: 0,
                consume: true,
            }],
            outputs,
            programs: vec![],
            state_creations: vec![],
            validation_scripts: vec![],
            payload: vec![],
        };
        let tx = draft.prepare().unwrap().transaction;
        point = OutPoint::new(tx.id(), 0);
        note = tx.outputs[0].clone();
        let witness =
            SealWitness::<NoteSeal>::new(NoteWitness::new(tx).unwrap(), Default::default());
        contract.include(opid, witness.client, &witness.published);
        ids.push(NoteTxid(point.transaction_id.as_bytes()));
    }
    assert_eq!(contract.state().owned["amount"][0].assignment.seal.point(), point);
    (contract, ids)
}
