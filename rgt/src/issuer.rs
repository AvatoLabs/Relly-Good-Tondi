//! Issuer for a numeric allocation that moves in full from one Note to the next.
use amplify::{confinement::Confined, num::u256};
use anyhow::Result;
use rgt::{
    aluvm::{
        alu::{Lib, LibSite},
        FIELD_ORDER_SECP,
    },
    Api, Codex, Issuer, OwnedApi, Semantics, StateArithm, StateBuilder, StateConvertor,
};
use strict_types::{SemId, Ty, TypeSystem};

pub fn whole_allocation() -> Result<Issuer> {
    // Genesis can issue from no destructible inputs. Delivery requires a consumed seal.
    let issue = Lib::assemble(&rgt::uasm! { cknxi destructible; not CO; chk CO; stop; })?;
    // Move exactly one cell, preserving both its type tag and amount.
    let transfer = Lib::assemble(&rgt::uasm! {
        ldi destructible; chk CO; mov E2, EA; mov E3, EB;
        cknxi destructible; not CO; chk CO;
        ldo destructible; chk CO; eq E2, EA; chk CO; eq E3, EB; chk CO;
        cknxo destructible; not CO; chk CO; stop;
    })?;
    let codex = Codex {
        name: "NoteTransfer".parse()?,
        developer: Default::default(),
        version: Default::default(),
        timestamp: 0,
        features: Default::default(),
        field_order: FIELD_ORDER_SECP,
        input_config: Default::default(),
        verification_config: Default::default(),
        verifiers: Confined::try_from_iter([
            (0, LibSite::new(issue.lib_id(), 0)),
            (1, LibSite::new(transfer.lib_id(), 0)),
        ])?,
    };
    let ty = Ty::<SemId>::U64;
    let sem_id = ty.sem_id_unnamed();
    let types = TypeSystem::from(Confined::try_from_iter([(sem_id, ty)])?);
    let amount = OwnedApi {
        sem_id,
        arithmetics: StateArithm::Fungible,
        convertor: StateConvertor::TypedEncoder(u256::ZERO),
        builder: StateBuilder::TypedEncoder(u256::ZERO),
        witness_sem_id: SemId::unit(),
        witness_builder: StateBuilder::TypedEncoder(u256::ZERO),
    };
    let api = Api {
        codex_id: codex.codex_id(),
        conforms: Default::default(),
        default_call: None,
        global: Default::default(),
        owned: Confined::try_from_iter([("amount".into(), amount)])?,
        aggregators: Default::default(),
        verifiers: Confined::try_from_iter([("issue".into(), 0), ("transfer".into(), 1)])?,
        errors: Default::default(),
    };
    Ok(Issuer::new(
        codex,
        Semantics {
            version: 0,
            default: api,
            custom: Default::default(),
            codex_libs: Confined::try_from_iter([issue, transfer])?,
            api_libs: Default::default(),
            types,
        },
    )?)
}
