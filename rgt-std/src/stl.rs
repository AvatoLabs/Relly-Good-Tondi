// Standard Library for RGT smart contracts
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2025 RGB Consortium, Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
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

use rgt::note::{note_stl, NoteSeal};
use commit_verify::stl::commit_verify_stl;
use hypersonic::aluvm::alu::stl::aluvm_stl;
use hypersonic::aluvm::zkstl::finite_field_stl;
use hypersonic::stl::{sonic_stl, usonic_stl};
use rgt::LIB_NAME_RGT;
use single_use_seals::SealWitness;
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typelib::LibBuilder;
use strict_types::{CompileError, TypeLib};

use crate::TransferHistory;

/// Strict types id for the library providing data types for RGT types.
pub const LIB_ID_RGT: &str =
    "stl:XYlnas2b-X7eSDWD-llKSRF3-jiYQH~8-y6PWvok-IMDbd40#crimson-portal-office";

#[allow(clippy::result_large_err)]
fn _rgt_seals() -> Result<TypeLib, CompileError> {
    LibBuilder::with(
        libname!("SingleUseSeals"),
        [
            std_stl().to_dependency_types(),
            commit_verify_stl().to_dependency_types(),
            note_stl().to_dependency_types(),
        ],
    )
    .transpile::<SealWitness<NoteSeal>>()
    .compile()
}

#[allow(clippy::result_large_err)]
fn _rgt_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::with(
        libname!(LIB_NAME_RGT),
        [
            std_stl().to_dependency_types(),
            strict_types_stl().to_dependency_types(),
            commit_verify_stl().to_dependency_types(),
            aluvm_stl().to_dependency_types(),
            finite_field_stl().to_dependency_types(),
            usonic_stl().to_dependency_types(),
            sonic_stl().to_dependency_types(),
            note_stl().to_dependency_types(),
            rgt_seals().to_dependency_types(),
        ],
    )
    .transpile::<TransferHistory<NoteSeal>>()
    .compile()
}

/// Generates a version of SingleUseSeal strict type library specific for RGT.
pub fn rgt_seals() -> TypeLib {
    _rgt_seals().expect("invalid strict type SingleUseSeals library")
}

/// Generates a strict type library providing data types for RGT types.
pub fn rgt_stl() -> TypeLib {
    _rgt_stl().expect("invalid strict type RGT library")
}

#[cfg(test)]
mod test {
    #![cfg_attr(coverage_nightly, coverage(off))]

    use super::*;

    #[test]
    fn lib_id() {
        let lib = rgt_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGT);
    }
}
