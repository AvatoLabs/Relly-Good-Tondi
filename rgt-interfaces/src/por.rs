// Collection of the standard RGT smart contract interface
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by RGB Consortium members & contributors
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2025 RGB Consortium members & contributors
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use amplify::confinement::SmallBlob;
use rgt_core::note::{NoteSeal, NoteTxid};
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::StrictVal;

use crate::LIB_NAME_RGT_CONTRACT;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGT_CONTRACT, tags = custom, dumb = Self::Note(strict_dumb!()))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Layer1Ptr {
    #[from]
    #[strict_type(tag = 0x0a)]
    Note(NoteSeal),
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGT_CONTRACT, dumb = ProofOfReserves::new(strict_dumb!(), strict_dumb!()))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProofOfReserves {
    pub note: NoteSeal,
    pub proof: SmallBlob,
}
impl StrictSerialize for ProofOfReserves {}
impl StrictDeserialize for ProofOfReserves {}

impl ProofOfReserves {
    pub fn new(note: NoteSeal, proof: SmallBlob) -> ProofOfReserves {
        ProofOfReserves { note, proof }
    }

    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        let note = value.unwrap_struct("note");
        let txid = NoteTxid(note.unwrap_struct("txid").unwrap_bytes().try_into().expect("32-byte Note transaction ID"));
        let vout: u32 = note.unwrap_struct("vout").unwrap_uint();
        let note = NoteSeal { txid, vout };

        let proof = SmallBlob::from_checked(value.unwrap_struct("proof").unwrap_bytes().into());

        Self { note, proof }
    }
}
