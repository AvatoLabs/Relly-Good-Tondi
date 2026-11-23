mod utils;
use rgt::{note::NoteSeal, Consensus, Contracts, Operation};
use rgt_persist_fs::StockpileDir;
use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    fs,
};

#[test]
fn export_and_import_note_history() {
    let dir = tempfile::tempdir().unwrap();
    let (contract, _) = utils::setup(dir.path());
    let file = dir.path().join("receiver.rgt");
    contract
        .export_history_to_file(&file, contract.full_state().raw.auth.keys())
        .unwrap();

    let storage = tempfile::tempdir().unwrap();
    let stock =
        StockpileDir::<NoteSeal>::load(storage.path().to_owned(), Consensus::TondiTestnet).unwrap();
    let mut contracts = Contracts::<_, HashMap<_, _>, HashMap<_, _>>::load(stock);
    let resolver = |_: &Operation| BTreeMap::new();
    let unsigned =
        |_, _: &rgt::Identity, _: &rgt::SigBlob| -> Result<(), Infallible> { unreachable!() };
    assert!(contracts
        .consume_from_file(false, &file, resolver, unsigned)
        .is_err());
    contracts
        .consume_from_file(true, &file, resolver, unsigned)
        .unwrap();
    contracts
        .consume_from_file(false, &file, resolver, unsigned)
        .unwrap();

    let mut wrong = fs::read(&file).unwrap();
    let original = wrong.clone();
    wrong[10..12].copy_from_slice(&0u16.to_le_bytes());
    fs::write(&file, &wrong).unwrap();
    assert!(contracts.consume_from_file(true, &file, resolver, unsigned).is_err());
    wrong = original;
    wrong[..8].copy_from_slice(b"RGBCNSGN");
    fs::write(&file, wrong).unwrap();
    assert!(contracts
        .consume_from_file(true, &file, resolver, unsigned)
        .is_err());
}
