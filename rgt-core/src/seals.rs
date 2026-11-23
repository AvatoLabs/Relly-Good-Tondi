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

use core::fmt::{Debug, Display};
use core::hash::Hash;

use single_use_seals::{ClientSideWitness, PublishedWitness, SingleUseSeal};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};
use ultrasonic::AuthToken;

/// A type which serves as a definition of a single-use seal for RGT contracts.
///
/// The reason why this type is required additionally to the [`RgtSeal`] type: under some protocols
/// (like Tondi UTXO-based single-use seals) the seal definition may be defined relatively to a
/// witness of previously closed seal, whose id is not known during seal definition construction.
/// In such cases, a seal definition should be converted into a full single-use seal instance using
/// the [`Self::resolve`] method.
pub trait RgtSealDef: Clone + Eq + Debug + Display + StrictDumb + StrictEncode + StrictDecode {
    /// A type providing implementation of a single-use seal protocol, under which this seal
    /// definition is applicable.
    type Src: RgtSeal;

    /// Convert seal definition into an [`AuthToken`] for the SONIC computer.
    fn auth_token(&self) -> AuthToken;

    /// Resolve seal definition into a complete single-use seal instance using the provided witness
    /// id information.
    ///
    /// # Nota bene
    ///
    /// The `witness_id` here is related not to the witness of the closing of this seal, but to a
    /// witness of the closing of some previous seal, relatively to which this seal is defined.
    fn resolve(
        &self,
        witness_id: <<Self::Src as SingleUseSeal>::PubWitness as PublishedWitness<Self::Src>>::PubId,
    ) -> Self::Src;

    /// Try to convert this seal definition into a complete single-use seal instance.
    ///
    /// The operation may result in `None` if additional information about the seal witness is
    /// required. In this case use [`Self::resolve`] method.
    fn to_src(&self) -> Option<Self::Src>;
}

/// A type which serves as a single-use seal protocol implementation for RGT contracts.
pub trait RgtSeal:
    SingleUseSeal<Message: From<[u8; 32]>, PubWitness = Self::Published, CliWitness = Self::Client> + Ord
{
    /// A type providing corresponding single-use seal definitions.
    type Definition: RgtSealDef<Src = Self>;
    /// A type for the published part of the single-use seal witness.
    type Published: PublishedWitness<Self, PubId = Self::WitnessId>;
    /// A type for the client-side part of the single-use seal witness.
    type Client: ClientSideWitness;
    /// A type for the id information about the single-use seal witness.
    type WitnessId: Copy + Ord + Hash + Debug + Display;
}
