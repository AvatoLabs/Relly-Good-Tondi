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

use rgt_core::note::note_stl;
use commit_verify::stl::commit_verify_stl;
use strict_types::stl::std_stl;
use strict_types::{LibBuilder, SemId, SymbolicSys, SystemBuilder, TypeLib, TypeSystem};

use crate::{
    Amount, AssetName, Details, EmbeddedMedia, Nft, NftSpec, OwnedNft, Precision, ProofOfReserves, Ticker,
    LIB_NAME_RGT_NFT, LIB_NAME_RGT_CONTRACT,
};

/// Strict types id for the library providing data types for RGT contracts.
pub const LIB_ID_RGT_INTERFACES: &str = "stl:eJWrHKTv-VjUk7QV-dQXLGjg-DmosJZX-4xIz4Mc-zzFeqPo#elite-detect-complex";

/// Strict types id for the library providing data types for RgtNft.
pub const LIB_ID_RGT_NFT: &str = "stl:HdamQQhH-R7G37Ac-P7qFs46-QnmMMJy-bZrEeg~-2aAEiHI#member-modular-frank";

pub fn rgt_contract_stl() -> TypeLib {
    LibBuilder::with(
        libname!(LIB_NAME_RGT_CONTRACT),
        [std_stl().to_dependency_types(), note_stl().to_dependency_types()],
    )
    .transpile::<Amount>()
    .transpile::<Precision>()
    .transpile::<Ticker>()
    .transpile::<AssetName>()
    .transpile::<Details>()
    .transpile::<ProofOfReserves>()
    .compile()
    .expect("invalid common types library")
}

pub fn rgt_nft_stl() -> TypeLib {
    LibBuilder::with(
        libname!(LIB_NAME_RGT_NFT),
        [
            std_stl().to_dependency_types(),
            rgt_contract_stl().to_dependency_types(),
            commit_verify_stl().to_dependency_types(),
            note_stl().to_dependency_types(),
        ],
    )
    .transpile::<Nft>()
    .transpile::<OwnedNft>()
    .transpile::<NftSpec>()
    .transpile::<EmbeddedMedia>()
    .compile()
    .expect("invalid common types library")
}

#[derive(Debug)]
pub struct CommonTypes(SymbolicSys);

impl Default for CommonTypes {
    fn default() -> Self {
        CommonTypes::new()
    }
}

impl CommonTypes {
    pub fn new() -> Self {
        Self(
            SystemBuilder::new()
                .import(std_stl())
                .unwrap()
                .import(note_stl())
                .unwrap()
                .import(rgt_contract_stl())
                .unwrap()
                .finalize()
                .unwrap(),
        )
    }

    pub fn type_system(&self) -> TypeSystem {
        let types = rgt_contract_stl().types;
        let types = types.iter().map(|(tn, ty)| ty.sem_id_named(tn));
        self.0.as_types().extract(types).unwrap()
    }

    pub fn get(&self, name: &'static str) -> SemId {
        *self
            .0
            .resolve(name)
            .unwrap_or_else(|| panic!("type '{name}' is absent in RGT contract common type library"))
    }
}

#[derive(Debug)]
pub struct RgtNftTypes(SymbolicSys);

impl Default for RgtNftTypes {
    fn default() -> Self {
        RgtNftTypes::new()
    }
}

impl RgtNftTypes {
    pub fn new() -> Self {
        Self(
            SystemBuilder::new()
                .import(std_stl())
                .unwrap()
                .import(rgt_contract_stl())
                .unwrap()
                .import(commit_verify_stl())
                .unwrap()
                .import(note_stl())
                .unwrap()
                .import(rgt_nft_stl())
                .unwrap()
                .finalize()
                .unwrap(),
        )
    }

    pub fn type_system(&self) -> TypeSystem {
        let types = rgt_nft_stl()
            .types
            .into_iter()
            .chain(rgt_contract_stl().types)
            .map(|(tn, ty)| ty.sem_id_named(&tn));
        self.0.as_types().extract(types).unwrap()
    }

    pub fn get(&self, name: &'static str) -> SemId {
        *self
            .0
            .resolve(name)
            .unwrap_or_else(|| panic!("type '{name}' is absent in RgtNft type library"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn common_lib_id() {
        let lib = rgt_contract_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGT_INTERFACES);
    }

    #[test]
    fn rgt_nft_lib_id() {
        let lib = rgt_nft_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGT_NFT);
    }
}
