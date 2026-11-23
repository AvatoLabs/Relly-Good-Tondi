// RGT Core Library: consensus layer for RGT smart contracts.
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

// TODO: Activate no_std once StrictEncoding will support it
// #![cfg_attr(not(feature = "std"), no_std)]
#![deny(
    unsafe_code,
    dead_code,
    missing_docs,
    unused_variables,
    unused_mut,
    unused_imports,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case
)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! RGT is confidential and scalable client-validated smart contracts for Tondi.
//!
//! RGT Core library provides consensus-critical and validation code for RGT. It is a standard
//! implementation defining RGT consensus and validation rules for the Tondi-native runtime.

extern crate alloc;
#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;
extern crate core;

mod verify;
mod seals;
/// Tondi v10 Note seals and publication witnesses.
pub mod note;

pub use seals::{RgtSeal, RgtSealDef};
pub use single_use_seals::*;
pub use verify::{ContractApi, ContractVerify, OperationSeals, ReadOperation, VerificationError};

/// Strict type library name for all RGT-related types.
pub const LIB_NAME_RGT: &str = "RGT";
