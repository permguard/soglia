// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Components that exist as interfaces but are not active in this build.
//!
//! Phase 0 keeps the boundaries of later phases in the code so they can be activated without
//! redesigning the process model. A deferred component never pretends to work: asking it to become
//! active is an error, never a silent allow.

use std::fmt;

/// Why a component cannot run in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// Part of the architecture, deliberately inactive in Phase 0.
    DisabledInPhase0(DeferredComponent),
    /// An implementation this build does not carry.
    UnsupportedInThisBuild(DeferredComponent),
}

impl fmt::Display for Unavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DisabledInPhase0(component) => {
                write!(
                    formatter,
                    "{component} is disabled in Phase 0 (DisabledInPhase0)"
                )
            }
            Self::UnsupportedInThisBuild(component) => write!(
                formatter,
                "{component} is not supported in this build (UnsupportedInThisBuild)"
            ),
        }
    }
}

impl std::error::Error for Unavailable {}

/// The components of later phases that Phase 0 carries only as interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferredComponent {
    /// The client of the Permguard Trust Fabric (Control, Data and Trust Plane).
    TrustFabricClient,
    /// PIC continuation and virtual authority (VPCA).
    PicContinuation,
    /// Information-flow control.
    Ifc,
    /// Credential substitution toward non-PIC-aware services.
    CredentialAnchor,
    /// Leaf-certificate signing for TLS interception.
    CaSigner,
    /// gRPC mediation.
    GrpcProxy,
    /// The cgroup-BPF enforcement backend.
    CgroupBpfBackend,
}

impl DeferredComponent {
    /// Every deferred component, in a stable order.
    pub const ALL: [Self; 7] = [
        Self::TrustFabricClient,
        Self::PicContinuation,
        Self::Ifc,
        Self::CredentialAnchor,
        Self::CaSigner,
        Self::GrpcProxy,
        Self::CgroupBpfBackend,
    ];

    /// Asks the component to become active on the request path.
    ///
    /// Always an error in this build: the architecture defines the component, Phase 0 does not run
    /// it. The cgroup-BPF backend is an implementation this build does not carry; everything else is
    /// deliberately disabled.
    pub fn activate(self) -> Result<(), Unavailable> {
        match self {
            Self::CgroupBpfBackend => Err(Unavailable::UnsupportedInThisBuild(self)),
            _ => Err(Unavailable::DisabledInPhase0(self)),
        }
    }
}

impl fmt::Display for DeferredComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TrustFabricClient => "the Permguard Trust Fabric client",
            Self::PicContinuation => "PIC continuation",
            Self::Ifc => "information-flow control",
            Self::CredentialAnchor => "the Credential Anchor",
            Self::CaSigner => "the CA signer",
            Self::GrpcProxy => "the gRPC proxy",
            Self::CgroupBpfBackend => "the cgroup-BPF enforcement backend",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_deferred_component_can_be_activated() {
        for component in DeferredComponent::ALL {
            let refused = component
                .activate()
                .expect_err("a deferred component must refuse");
            match component {
                DeferredComponent::CgroupBpfBackend => {
                    assert_eq!(refused, Unavailable::UnsupportedInThisBuild(component));
                }
                _ => assert_eq!(refused, Unavailable::DisabledInPhase0(component)),
            }
        }
    }

    #[test]
    fn the_refusal_names_its_kind() {
        let disabled = DeferredComponent::Ifc.activate().expect_err("refused");
        assert!(disabled.to_string().contains("DisabledInPhase0"));

        let unsupported = DeferredComponent::CgroupBpfBackend
            .activate()
            .expect_err("refused");
        assert!(unsupported.to_string().contains("UnsupportedInThisBuild"));
    }
}
