//! Receipt statement for the RGT single-cell profile. The same relation runs on host and guest.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use strict_encoding::{StrictDecode, StrictEncode, StrictReader, StrictWriter};
#[allow(warnings)]
#[path = "../../../Tondi/vm/guest/generated/tondi.rs"]
mod packed;
#[allow(warnings)]
#[path = "../../../Tondi/vm/src/telegraph.rs"]
mod telegraph;
use packed::{InputUnionReader, TransactionBodyReader};
use telegraph::{prelude::Reader, uleb_value};
use ultrasonic::{
    AuthToken, CellAddr, Issue, LibRepo, Memory, Operation, StateCell, StateValue,
    aluvm::alu::{Lib, LibId},
};

pub const LIMIT: usize = 1 << 20;
pub fn encode<T: StrictEncode>(v: &T) -> Vec<u8> {
    v.strict_encode(StrictWriter::in_memory::<LIMIT>()).expect("bounded strict value").unbox().unconfine()
}
pub fn decode<T: StrictDecode>(bytes: &[u8]) -> T {
    assert!(bytes.len() <= LIMIT);
    let mut reader = StrictReader::in_memory::<LIMIT>(bytes);
    let value = T::strict_decode(&mut reader).expect("invalid strict value");
    assert_eq!(reader.into_cursor().position() as usize, bytes.len());
    value
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opening {
    pub txid: Option<[u8; 32]>,
    pub vout: u32,
    pub auth: [u8; 32],
    pub blinding: [u8; 32],
}
impl Opening {
    pub fn token(&self) -> AuthToken {
        let mut h = blake3::Hasher::new_derive_key("RGT/Tondi-v10/note-seal/v1");
        h.update(&[u8::from(self.txid.is_some())]);
        if let Some(id) = self.txid {
            h.update(&id);
        }
        h.update(&self.vout.to_le_bytes());
        h.update(&self.auth);
        h.update(&self.blinding);
        AuthToken::from_byte_array(h.finalize().as_bytes()[..30].try_into().unwrap())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frontier {
    pub genesis: [u8; 32],
    pub network: [u8; 32],
    pub contract: [u8; 32],
    pub opid: [u8; 32],
    pub txid: [u8; 32],
    pub opening: Opening,
    pub cell: Vec<u8>,
}
impl Frontier {
    /// A fixed-size public journal. The recipient opens it with its private state.
    pub fn journal(&self, image: [u32; 8]) -> Vec<u8> {
        let mut hash = Sha256::new();
        hash.update(b"RGT/recursive/one-cell/v1");
        for field in [self.genesis, self.network, self.contract, self.opid, self.txid] {
            hash.update(field);
        }
        hash.update(self.opening.vout.to_le_bytes());
        hash.update(self.opening.auth);
        hash.update(self.opening.token().to_byte_array());
        hash.update((self.cell.len() as u64).to_le_bytes());
        hash.update(&self.cell);
        let mut out = Vec::with_capacity(64);
        for word in image {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.extend_from_slice(&hash.finalize());
        out
    }
}
#[derive(Serialize, Deserialize)]
pub struct Step {
    pub genesis: [u8; 32],
    pub network: [u8; 32],
    pub issue: Vec<u8>,
    pub libs: Vec<Vec<u8>>,
    pub opening: Opening,
    pub transfer: Option<Transfer>,
}
#[derive(Serialize, Deserialize)]
pub struct Transfer {
    pub previous: Frontier,
    pub operation: Vec<u8>,
    pub body: Vec<u8>,
}

struct Prior(Option<(CellAddr, StateCell)>);
impl Memory for Prior {
    fn destructible(&self, addr: CellAddr) -> Option<StateCell> {
        self.0.filter(|(a, _)| *a == addr).map(|(_, c)| c)
    }
    fn immutable(&self, _: CellAddr) -> Option<StateValue> {
        None
    }
}
struct Libraries(Vec<Lib>);
impl LibRepo for Libraries {
    fn get_lib(&self, id: LibId) -> Option<&Lib> {
        self.0.iter().find(|lib| lib.lib_id() == id)
    }
}

/// Verify the codex, previous cell, native consumed outpoint and exact successor commitment.
/// A transfer's caller must authenticate its predecessor journal before using the returned state.
pub fn advance(step: &Step) -> Frontier {
    let issue: Issue = decode(&step.issue);
    let id = issue.contract_id();
    assert_eq!(issue.genesis.codex_id, issue.codex_id());
    let libs = Libraries(step.libs.iter().map(|lib| decode(lib)).collect());
    let (op, prior, txid) = if let Some(t) = &step.transfer {
        let prev = &t.previous;
        assert_eq!((prev.genesis, prev.network, prev.contract), (step.genesis, step.network, id.to_byte_array()));
        let op: Operation = decode(&t.operation);
        assert_eq!(op.destructible_in.len(), 1);
        assert_eq!(op.destructible_out.len(), 1);
        let addr = CellAddr::new(prev.opid.into(), 0);
        assert_eq!(op.destructible_in[0].addr, addr);
        let cell: StateCell = decode(&prev.cell);
        assert_eq!(op.destructible_out[0].data, cell.data);
        assert_eq!(cell.auth, prev.opening.token());
        assert!(step.opening.txid.is_none());
        let body = TransactionBodyReader::from_slice(&t.body).expect("canonical Telegraph body");
        assert_eq!(body.version().as_slice(), 1u16.to_le_bytes());
        assert_eq!(body.network().as_slice(), step.network);
        assert!(body.inputs().iter().any(|input| match input.to_enum() {
            InputUnionReader::ConsumeInput(c) =>
                c.previous_outpoint().transaction_id().as_slice() == prev.txid
                    && uleb_value(c.previous_outpoint().index().as_slice()) == prev.opening.vout as u128,
            InputUnionReader::ReferenceInput(_) => false,
        }));
        let anchor = blake3::derive_key("RGT/Tondi-v10/operation/v1", &op.opid().to_byte_array());
        let mut count = 0;
        for (i, note) in body.outputs().iter().enumerate() {
            for facet in note.facets().iter().filter(|f| f.key().as_slice() == 0x5254u16.to_le_bytes()) {
                assert_eq!(i, 0);
                assert!(facet.state_id().as_slice().is_empty());
                assert_eq!(facet.data().raw_data(), anchor);
                count += 1;
            }
        }
        assert_eq!(count, 1);
        let output = body.outputs().get(step.opening.vout as usize).expect("successor output");
        assert_eq!(output.auth().script_hash().as_slice(), step.opening.auth);
        (op, Prior(Some((addr, cell))), blake3::derive_key("Tondi/transaction-body", &t.body))
    } else {
        let op = issue.genesis.to_operation(id);
        assert!(op.destructible_in.is_empty());
        (op, Prior(None), step.opening.txid.expect("genesis Note"))
    };
    assert!(op.immutable_in.is_empty() && op.immutable_out.is_empty());
    assert_eq!(op.destructible_out.len(), 1);
    let cell = op.destructible_out[0];
    assert_eq!(cell.auth, step.opening.token());
    let opid = op.opid().to_byte_array();
    issue.codex.verify(id, op, &prior, &libs).expect("invalid asset transition");
    Frontier {
        genesis: step.genesis,
        network: step.network,
        contract: id.to_byte_array(),
        txid,
        opid,
        opening: step.opening.clone(),
        cell: encode(&cell),
    }
}
