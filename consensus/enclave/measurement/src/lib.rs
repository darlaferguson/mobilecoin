// Copyright (c) 2018-2022 The MobileCoin Foundation

#![no_std]
#![doc = include_str!("../README.md")]

use mc_attest_core::SecurityVersion;
use mc_attest_verifier_config::{
    TrustedMeasurement, TrustedMrEnclaveMeasurement, TrustedMrSignerMeasurement,
};
use mc_sgx_css::Signature;

pub fn sigstruct() -> Signature {
    Signature::try_from(&include_bytes!(env!("MCBUILD_ENCLAVE_CSS_PATH"))[..])
        .expect("Could not read measurement signature")
}

pub const CONFIG_ADVISORIES: &[&str] = &[];
pub const HARDENING_ADVISORIES: &[&str] = &["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"];

pub fn mr_signer_measurement(
    override_minimum_svn: impl Into<Option<SecurityVersion>>,
) -> TrustedMeasurement {
    let signature = sigstruct();

    let mr_signer = TrustedMrSignerMeasurement::new(
        &signature.mrsigner(),
        signature.product_id(),
        override_minimum_svn
            .into()
            .unwrap_or_else(|| signature.version()),
        CONFIG_ADVISORIES,
        HARDENING_ADVISORIES,
    );
    mr_signer.into()
}

pub fn mr_enclave_measurement() -> TrustedMeasurement {
    let signature = sigstruct();

    let mr_enclave = TrustedMrEnclaveMeasurement::new(
        signature.mrenclave(),
        CONFIG_ADVISORIES,
        HARDENING_ADVISORIES,
    );
    mr_enclave.into()
}
