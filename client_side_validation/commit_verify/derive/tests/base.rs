// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems
// (InDCS), Switzerland. Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

#![allow(unused_braces)]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;

mod common;

use std::fmt::Display;

use amplify::{Bytes32, Wrapper};
use commit_verify::{CommitEncode, CommitId, CommitmentId, Conceal, DigestExt, TondiBlake3};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

const TEST_LIB: &str = "TestLib";

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
#[display(inner)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = TEST_LIB)]
struct DumbId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl CommitmentId for DumbId {
    const TAG: &'static str = "";
}

impl From<TondiBlake3> for DumbId {
    fn from(value: TondiBlake3) -> Self {
        value.finish().into()
    }
}

fn verify_commit<T: CommitId>(value: T, expect: &'static str)
where
    T::CommitmentId: Display,
{
    assert_eq!(&value.commit_id().to_string(), expect, "invalid commitment");
}

#[test]
fn strategy_transparent() -> common::Result {
    #[derive(Wrapper, Clone, PartialEq, Eq, Debug, From)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = transparent, id = DumbId)]
    struct ShortLen(u16);

    verify_commit(ShortLen(0), "5d3b955be18c815716feb914f4d766c9189a282a45a11bbb6a24376d673d947a");
    #[allow(clippy::mixed_case_hex_literals)]
    verify_commit(
        ShortLen(0xFFde),
        "813c2109c503802d88cda46a5d0e2a998af3212ffa183e3ec7ffc216a679a277",
    );

    Ok(())
}

#[test]
fn strategy_strict_enum() -> common::Result {
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = repr, into_u8, try_from_u8)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict, id = DumbId)]
    #[repr(u8)]
    enum Prim {
        #[strict_type(dumb)]
        A,
        B,
        C,
    }

    verify_commit(Prim::A, "2cd5440b15682ddcb40ceb529ff1d20fe1b0120290e6eecae5988704d91c3460");
    verify_commit(Prim::B, "5363bcacbd9912c1739ba1ffb5d4363596307655b616d3d26300918aeeb1a8cc");
    verify_commit(Prim::C, "c452d5c154613f6f0b2d92c1164dc32e090e10bbc7d38791bb38a985c4b58eb2");

    Ok(())
}

#[test]
fn strategy_strict_tuple() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict, id = DumbId)]
    struct TaggedInfo(u16, u64);

    verify_commit(
        TaggedInfo(0xdead, 0xbeefcafebaddafec),
        "55dc92ab9047dbbed0762924fde15fcdc05e4db7eb323f4b2b5114edef47311d",
    );

    Ok(())
}

#[test]
fn strategy_strict_struct() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict, id = DumbId)]
    struct TaggedInfo {
        a: u16,
        b: u64,
    }

    verify_commit(
        TaggedInfo {
            a: 0xdead,
            b: 0xbeefcafebaddafec,
        },
        "55dc92ab9047dbbed0762924fde15fcdc05e4db7eb323f4b2b5114edef47311d",
    );

    Ok(())
}

#[test]
fn enum_associated() -> common::Result {
    #[allow(dead_code)]
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = order)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict, id = DumbId)]
    enum Assoc {
        One {
            hash: [u8; 32],
            ord: u8,
        },
        Two(u8, u16, u32),
        #[strict_type(dumb)]
        Three,
        Four(),
        Five {},
    }

    verify_commit(
        Assoc::One {
            hash: default!(),
            ord: 1,
        },
        "6ccb34da4920bd64a04fe680dba91351fe93862f8c87e738b08106c78ce73e5b",
    );

    Ok(())
}

#[test]
fn enum_custom_tags() -> common::Result {
    #[allow(dead_code)]
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = order)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict, id = DumbId)]
    enum Assoc {
        #[strict_type(tag = 8)]
        One { hash: [u8; 32], ord: u8 },
        #[strict_type(tag = 2)]
        Two(u8, u16, u32),
        #[strict_type(dumb, tag = 3)]
        Three,
        #[strict_type(tag = 4)]
        Four(),
        #[strict_type(tag = 5)]
        Five {},
    }

    let mut res = vec![8; 33];
    res.extend([1]);
    verify_commit(
        Assoc::One {
            hash: [8; 32],
            ord: 1,
        },
        "e2e94c6ffee482beb726d4e41c708bf49b9b7f4c480be527e08d64d484335dfa",
    );

    Ok(())
}

#[test]
fn conceal() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = order, dumb = { Self::Concealed(0) })]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = conceal, id = DumbId)]
    enum Data {
        Revealed(u128),
        Concealed(u8),
    }

    impl Conceal for Data {
        type Concealed = Self;
        fn conceal(&self) -> Self {
            Self::Concealed(0xde)
        }
    }

    verify_commit(
        Data::Revealed(0xcafe1234),
        "d0929142cf5cfbe9a95d226d355e7fe039eacecef0fc66b46b8a3ea722b6f7e2",
    );

    Ok(())
}

/* TODO: Refactor
#[test]
fn merklize() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(CommitEncode)]
    struct Tree {
        #[commit_encode(merklize = MERKLE_LNPBP4_TAG)]
        leaves: SmallVec<Leaf>,
    }

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
    #[derive(CommitEncode)]
    pub struct Leaf(u16);
    impl CommitmentId for Leaf {
        const TAG: [u8; 32] = [0u8; 32];
        type Id = MerkleHash;
    }

    let test_vec = small_vec!(Leaf(0), Leaf(1), Leaf(2), Leaf(3));
    verify_commit(
        Tree {
            leaves: test_vec.clone(),
        },
        MerkleHash::merklize(&test_vec).as_slice(),
    );

    Ok(())
}
 */
