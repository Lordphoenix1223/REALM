//! Host-side Linux boundary inspection. The missing VM/network/device/monitor
//! measurements remain `Unavailable`, so this module cannot authorize reuse.

use crate::capsule::{CheckResult, HostChecks};
use crate::{Admission, Receipt, Refusal, World, validate_receipt};
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Serialize)]
pub struct BoundaryReport {
    pub cgroup_empty: CheckResult,
    pub checks: HostChecks,
    pub admission: Admission,
}

fn cgroup_empty(cgroup: &Path) -> CheckResult {
    let events = fs::read_to_string(cgroup.join("cgroup.events"));
    let processes = fs::read_to_string(cgroup.join("cgroup.procs"));
    let threads = fs::read_to_string(cgroup.join("cgroup.threads"));
    let (Ok(events), Ok(processes), Ok(threads)) = (events, processes, threads) else {
        return CheckResult::Unavailable;
    };
    let populated = events
        .lines()
        .find_map(|line| line.strip_prefix("populated "));
    match populated {
        Some("0") if processes.trim().is_empty() && threads.trim().is_empty() => {
            CheckResult::Verified
        }
        Some("0" | "1") => CheckResult::Failed,
        _ => CheckResult::Unavailable,
    }
}

fn scan_matches(root: &Path, expected: &World) -> CheckResult {
    match crate::linux_scan::scan_world_linux(root) {
        Ok(actual) if actual == *expected => CheckResult::Verified,
        Ok(_) | Err(Refusal::UnsupportedEffect | Refusal::ScanFailure) => CheckResult::Failed,
        Err(_) => CheckResult::Unavailable,
    }
}

/// Inspect only resources the host can currently measure. The caller must be a
/// separate host-owned process; paths supplied by an untrusted task have no authority.
pub fn inspect_boundary(
    receipt_bytes: &[u8],
    frozen_root: &Path,
    vm_cgroup: &Path,
) -> BoundaryReport {
    let parsed: Result<Receipt, _> = serde_json::from_slice(receipt_bytes);
    let (replay, world) = match parsed {
        Ok(ref receipt) => (validate_receipt(receipt), Some(&receipt.final_world)),
        Err(_) => (Err(Refusal::Malformed), None),
    };
    let world_check = match world {
        Some(world) => scan_matches(frozen_root, world),
        None => CheckResult::Unavailable,
    };
    let cgroup_check = cgroup_empty(vm_cgroup);
    // Empty text files alone do not bind this cgroup to the launched VM or
    // prove that descendants could not escape it.
    let process_check = if cgroup_check == CheckResult::Failed {
        CheckResult::Failed
    } else {
        CheckResult::Unavailable
    };
    let replay_check = if replay.is_ok() {
        CheckResult::Verified
    } else {
        CheckResult::Failed
    };
    let checks = HostChecks {
        frozen_world: world_check,
        process_and_fd_quiescence: process_check,
        network_boundary: CheckResult::Unavailable,
        device_boundary: CheckResult::Unavailable,
        executable_bytes: CheckResult::Unavailable,
        monitor_liveness_and_loss: CheckResult::Unavailable,
        effect_replay_agreement: replay_check,
    };
    let admission = if let Err(reason) = replay {
        Admission::Refuse(reason)
    } else if matches!(checks.frozen_world, CheckResult::Failed) {
        Admission::Refuse(Refusal::WorldMismatch)
    } else if matches!(checks.process_and_fd_quiescence, CheckResult::Failed) {
        Admission::Refuse(Refusal::ProcessLeak)
    } else {
        Admission::Refuse(Refusal::UnverifiedBoundary)
    };
    BoundaryReport {
        cgroup_empty: cgroup_check,
        checks,
        admission,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_parser_requires_empty_processes_and_populated_zero() {
        let root = std::env::temp_dir().join(format!("realm-v6-cgroup-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
        fs::write(root.join("cgroup.procs"), "").unwrap();
        fs::write(root.join("cgroup.threads"), "").unwrap();
        assert_eq!(cgroup_empty(&root), CheckResult::Verified);
        fs::write(root.join("cgroup.procs"), "42\n").unwrap();
        assert_eq!(cgroup_empty(&root), CheckResult::Failed);
        fs::remove_file(root.join("cgroup.events")).unwrap();
        assert_eq!(cgroup_empty(&root), CheckResult::Unavailable);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn producer_cannot_turn_empty_fake_cgroup_into_quiescence_authority() {
        let root =
            std::env::temp_dir().join(format!("realm-v6-fake-cgroup-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("cgroup.events"), "populated 0\n").unwrap();
        fs::write(root.join("cgroup.procs"), "").unwrap();
        fs::write(root.join("cgroup.threads"), "").unwrap();
        let report = inspect_boundary(b"{}", &root, &root);
        assert_eq!(report.cgroup_empty, CheckResult::Verified);
        assert_eq!(
            report.checks.process_and_fd_quiescence,
            CheckResult::Unavailable
        );
        assert_eq!(report.admission, Admission::Refuse(Refusal::Malformed));
        fs::remove_dir_all(root).unwrap();
    }
}
