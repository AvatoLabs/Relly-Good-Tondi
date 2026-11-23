mod utils;
use rgt::WitnessStatus;
use std::num::NonZeroU64;

#[test]
fn observes_certification_and_repeated_updates() {
    let dir = tempfile::tempdir().unwrap();
    let (mut contract, ids) = utils::setup(dir.path());
    let certified = WitnessStatus::Certified(NonZeroU64::new(4).unwrap());
    for _ in 0..2 {
        contract.sync([(ids[0], certified)]).unwrap();
        assert_eq!(
            contract
                .witnesses()
                .find(|w| w.id == ids[0])
                .unwrap()
                .status,
            certified
        );
    }
}

#[test]
fn archive_and_restore_pending_transfers() {
    let dir = tempfile::tempdir().unwrap();
    let (mut contract, ids) = utils::setup(dir.path());
    for status in [WitnessStatus::Archived, WitnessStatus::Tentative] {
        contract.sync(ids.iter().map(|id| (*id, status))).unwrap();
        for id in &ids {
            assert_eq!(contract.witnesses().find(|w| w.id == *id).unwrap().status, status);
        }
    }
}
