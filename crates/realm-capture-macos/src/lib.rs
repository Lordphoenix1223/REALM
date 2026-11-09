//! macOS Endpoint Security availability boundary.
//!
//! This crate intentionally does not synthesize ES events. Until the local
//! SDK/API and entitlement are proven, starting this backend fails explicitly.

use realm_capture::{CaptureBackend, CaptureBatch, CaptureError};
use realm_core::TransactionId;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointSecurityAvailability {
    pub platform: &'static str,
    pub local_sdk_has_standard_client_symbol: bool,
    pub local_sdk_has_message_retention: bool,
    pub local_sdk_has_descendants_symbol: bool,
    pub official_docs_describe_beta_api: bool,
    pub entitlement_proven: bool,
    pub real_capture_available: bool,
    pub reason: &'static str,
}

pub fn availability() -> EndpointSecurityAvailability {
    #[cfg(target_os = "macos")]
    {
        // Xcode 26.6's macOS 26.5 SDK headers inspected for this repository do
        // not declare es_new_descendants_client. Official online documentation
        // describes it as preliminary/beta, but that is not local link proof.
        EndpointSecurityAvailability {
            platform: "macOS",
            local_sdk_has_standard_client_symbol: true,
            local_sdk_has_message_retention: true,
            local_sdk_has_descendants_symbol: false,
            official_docs_describe_beta_api: true,
            entitlement_proven: false,
            real_capture_available: false,
            reason: "Endpoint Security entitlement and descendants-client link/runtime proof are absent",
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        EndpointSecurityAvailability {
            platform: "non-macOS",
            local_sdk_has_standard_client_symbol: false,
            local_sdk_has_message_retention: false,
            local_sdk_has_descendants_symbol: false,
            official_docs_describe_beta_api: false,
            entitlement_proven: false,
            real_capture_available: false,
            reason: "Endpoint Security is macOS-only",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CloneOutcome {
    Supported { source_size: u64, clone_size: u64 },
    NotSupported,
    CrossVolume,
    PermissionDenied,
    RaceDetected,
    Other { errno: Option<i32> },
}

/// Calls the documented public APFS clone API only when the caller supplies a
/// marker-owned source and a destination that does not already exist. The
/// function does not delete or overwrite either path.
pub fn probe_apfs_clone(source: &std::path::Path, destination: &std::path::Path) -> CloneOutcome {
    if destination.exists() {
        return CloneOutcome::Other { errno: None };
    }
    #[cfg(target_os = "macos")]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let Ok(source) = CString::new(source.as_os_str().as_bytes()) else {
            return CloneOutcome::Other { errno: None };
        };
        let Ok(destination) = CString::new(destination.as_os_str().as_bytes()) else {
            return CloneOutcome::Other { errno: None };
        };
        // SAFETY: both C strings are NUL-free and remain alive for the call.
        let result = unsafe { clonefile(source.as_ptr(), destination.as_ptr(), 0) };
        if result == 0 {
            let source_size = std::fs::metadata(source.to_string_lossy().as_ref())
                .map(|metadata| metadata.len())
                .unwrap_or_default();
            let clone_size = std::fs::metadata(destination.to_string_lossy().as_ref())
                .map(|metadata| metadata.len())
                .unwrap_or_default();
            return if source_size == clone_size {
                CloneOutcome::Supported {
                    source_size,
                    clone_size,
                }
            } else {
                CloneOutcome::RaceDetected
            };
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc_errno) if libc_errno == 1 || libc_errno == 13 => {
                CloneOutcome::PermissionDenied
            }
            Some(18) => CloneOutcome::CrossVolume,
            Some(libc_errno) if libc_errno == 45 || libc_errno == 95 => CloneOutcome::NotSupported,
            errno => CloneOutcome::Other { errno },
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (source, destination);
        CloneOutcome::NotSupported
    }
}

#[cfg(target_os = "macos")]
#[link(name = "System")]
unsafe extern "C" {
    fn clonefile(
        source: *const std::ffi::c_char,
        destination: *const std::ffi::c_char,
        flags: u32,
    ) -> i32;
}

#[derive(Debug, Error)]
pub enum MacOsCaptureError {
    #[error("real macOS capture is unavailable: {0}")]
    Unavailable(&'static str),
}

pub struct EndpointSecurityBackend;

impl EndpointSecurityBackend {
    pub fn new() -> Result<Self, MacOsCaptureError> {
        let state = availability();
        if !state.real_capture_available {
            return Err(MacOsCaptureError::Unavailable(state.reason));
        }
        Ok(Self)
    }
}

impl CaptureBackend for EndpointSecurityBackend {
    fn name(&self) -> &str {
        "macos-endpoint-security"
    }

    fn start(&mut self, _transaction_id: TransactionId) -> Result<(), CaptureError> {
        Err(CaptureError::Inactive)
    }

    fn stop(&mut self) -> Result<CaptureBatch, CaptureError> {
        Err(CaptureError::Inactive)
    }
}
