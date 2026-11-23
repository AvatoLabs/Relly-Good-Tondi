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

use std::convert::Infallible;
use std::error::Error;
use std::vec;

use amplify::confinement::{LargeVec, SmallOrdMap};
use amplify::ByteArray;
use commit_verify::{ReservedBytes, StrictHash};
use hypersonic::Articles;
use rgt::{OperationSeals, ReadOperation, RgtSeal, LIB_NAME_RGT};
use strict_encoding::{DecodeError, ReadRaw, StrictDecode, StrictReader, TypedRead};

use crate::{ContractId, Identity, Issue, SemanticError, Semantics, SigBlob};

pub const MAX_HISTORY_OPS: u32 = u16::MAX as u32;

#[derive(StrictType, StrictDumb, StrictEncode)]
#[strict_type(lib = LIB_NAME_RGT)]
pub struct TransferHistory<Seal: RgtSeal> {
    header: TransferHistoryHeader<Seal>,
    operation_seals: LargeVec<OperationSeals<Seal>>,
}

#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGT)]
struct TransferHistoryHeader<Seal: RgtSeal> {
    extensions: ReservedBytes<1>,
    semantics: Semantics,
    sig: Option<SigBlob>,
    issue: Issue,
    genesis_seals: SmallOrdMap<u16, Seal::Definition>,
    witness: ReservedBytes<1>,
    op_count: u32,
}

impl<Seal: RgtSeal> StrictDecode for TransferHistory<Seal> {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        let header = TransferHistoryHeader::<Seal>::strict_decode(reader)?;
        if header.op_count > MAX_HISTORY_OPS {
            return Err(DecodeError::DataIntegrityError(format!(
                "number of operations in contract history ({}) exceeds maximum allowed \
                 ({MAX_HISTORY_OPS})",
                header.op_count
            )));
        }
        let mut operation_seals = LargeVec::with_capacity(header.op_count as usize);
        for _ in 0..header.op_count {
            operation_seals
                .push(OperationSeals::<Seal>::strict_decode(reader)?)
                .ok();
        }

        Ok(Self { header, operation_seals })
    }
}

impl<Seal: RgtSeal> TransferHistory<Seal> {
    pub fn articles<E>(
        &self,
        sig_validator: impl FnOnce(StrictHash, &Identity, &SigBlob) -> Result<(), E>,
    ) -> Result<Articles, SemanticError> {
        Articles::with(
            self.header.semantics.clone(),
            self.header.issue.clone(),
            self.header.sig.clone(),
            sig_validator,
        )
    }

    pub(crate) fn into_operations(self) -> InMemOps<Seal> {
        let genesis = OperationSeals {
            operation: self
                .header
                .issue
                .genesis
                .to_operation(ContractId::from_byte_array(
                    self.header.issue.codex_id().to_byte_array(),
                )),
            defined_seals: self.header.genesis_seals,
            witness: None,
        };
        InMemOps(Some(genesis), self.operation_seals.into_iter())
    }
}

pub(crate) struct InMemOps<Seal: RgtSeal>(
    Option<OperationSeals<Seal>>,
    vec::IntoIter<OperationSeals<Seal>>,
);

impl<Seal: RgtSeal> ReadOperation for InMemOps<Seal> {
    type Seal = Seal;

    fn read_operation(
        &mut self,
    ) -> Result<Option<OperationSeals<Self::Seal>>, impl Error + 'static> {
        Result::<_, Infallible>::Ok(self.0.take().or_else(|| self.1.next()))
    }
}

pub fn parse_history(
    reader: &mut StrictReader<impl ReadRaw>,
) -> Result<ContractId, DecodeError> {
    if u16::strict_decode(reader)? != crate::HISTORY_VERSION {
        return Err(DecodeError::DataIntegrityError(s!("unsupported Note history version")));
    }
    ReservedBytes::<1>::strict_decode(reader).map_err(|e| {
        if matches!(e, DecodeError::DataIntegrityError(_)) {
            DecodeError::DataIntegrityError(s!("unsupported SONIC stream version"))
        } else {
            e
        }
    })?;
    ContractId::strict_decode(reader)
}
