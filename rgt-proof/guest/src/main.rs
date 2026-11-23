use rgt_lineage::{advance, Step};
use risc0_zkvm::guest::env;
fn main() {
    let image: [u32; 8] = env::read();
    let size: u32 = env::read();
    assert!(size <= 8 << 20);
    let mut bytes = vec![0; size as usize];
    env::read_slice(&mut bytes);
    let step: Step = serde_json::from_slice(&bytes).expect("RGT witness");
    if let Some(t) = &step.transfer {
        env::verify(image, &t.previous.journal(image)).unwrap();
    }
    env::commit_slice(&advance(&step).journal(image));
}
