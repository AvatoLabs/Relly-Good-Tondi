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

use rgt_interfaces::{rgt_nft_stl, rgt_contract_stl};
use strict_types::parse_args;

fn main() {
    let (format, dir) = parse_args();
    rgt_core::note::note_stl()
        .serialize(format, dir.as_ref(), "1.0.0", Some("\n  Description: Tondi v10 Note seals, openings and ordering witnesses."))
        .expect("unable to write Note types");

    let lib = rgt_contract_stl();
    lib.serialize(
        format,
        dir.as_ref(),
        "0.12.0",
        Some(
            "
  Collection of the standard RGT smart contract interface
  Author: Dr Maxim Orlovsky <orlovsky@ubideco.org>
  Copyright (C) 2019-2025 RGB Consortium members & contributors.
                          All rights reserved.
  License: Apache-2.0",
        ),
    )
    .expect("unable to write to the file");

    let lib = rgt_nft_stl();
    lib.serialize(
        format,
        dir.as_ref(),
        "0.12.0",
        Some(
            "
  RgtNft smart contract interface
  Author: Dr Maxim Orlovsky <orlovsky@ubideco.org>
  Copyright (C) 2019-2025 RGB Consortium members & contributors.
                          All rights reserved.
  License: Apache-2.0",
        ),
    )
    .expect("unable to write to the file");
}
