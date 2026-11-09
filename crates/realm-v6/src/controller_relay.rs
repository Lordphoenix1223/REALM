//! Shared bounded pipe relay. Internal dispatch never enters task/publication code.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    run_args(std::env::args().collect())
}
/// Exact early child-mode dispatch; malformed internal invocations refuse.
pub fn dispatch_internal() -> Option<Result<(), Box<dyn std::error::Error>>> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("--internal-coding-relay") {
        return None;
    }
    if args.len() != 3 {
        return Some(Err("exact internal relay binding argument required".into()));
    }
    Some(run_args(vec![
        args[0].clone(),
        "--relay".into(),
        args[2].clone(),
    ]))
}
use crate::{
    coding_submission::{MAX_FILE, PATHS, SubmissionContract},
    controller_guard,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    ffi::CString,
    io::{self, BufRead, Write},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    binding: SubmissionContract,
    sequence: u64,
    request: Request,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(tag = "tool", rename_all = "lowercase", deny_unknown_fields)]
enum Request {
    List,
    Read { path: String },
    Write { path: String, text: String },
    Check,
    Finish,
}
impl Request {
    fn valid(&self) -> bool {
        match self {
            Self::Read { path } => PATHS.contains(&path.as_str()),
            Self::Write { path, text } => PATHS.contains(&path.as_str()) && text.len() <= MAX_FILE,
            _ => true,
        }
    }
}
fn run_args(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() == 2 && args[1] == "--runtime-probe" {
        return runtime_probe();
    }
    if args.len() == 5 && args[1] == "--probe" {
        return probe(&args[2], &args[3], args[4].parse()?);
    }
    if args.as_slice().get(1).map(String::as_str) != Some("--relay") || args.len() != 3 {
        return Err(
            "--relay EXPECTED_BINDING_JSON or --probe PATH ALIAS INHERITED_FD required".into(),
        );
    }
    let expected: SubmissionContract = serde_json::from_value(
        crate::strict_json::parse(args[2].as_bytes())
            .map_err(|_| "strict expected binding required")?,
    )?;
    expected.validate()?;
    let policy_root = controller_guard::install()?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut finished = false;
    for sequence in 0..128 {
        let mut raw = Vec::new();
        std::io::Read::take(&mut input, 131073).read_until(b'\n', &mut raw)?;
        if raw.is_empty() {
            return if finished {
                Ok(())
            } else {
                Err("EOF before finish".into())
            };
        }
        if finished || raw.len() > 131072 || !raw.ends_with(b"\n") {
            return Err("frame boundary/closure refused".into());
        }
        let value = crate::strict_json::parse(&raw).map_err(|_| "strict JSON frame required")?;
        let frame: Frame = serde_json::from_value(value)?;
        frame.binding.validate()?;
        if frame.sequence != sequence || !frame.request.valid() || frame.binding != expected {
            return Err("sequence/run/path/scope differs".into());
        }
        finished = matches!(frame.request, Request::Finish);
        serde_json::to_writer(
            &mut output,
            &json!({"binding":frame.binding,"sequence":sequence,
            "request":frame.request,"policy":controller_guard::POLICY,"policy_root":policy_root,
            "authority":"NONE","complete_observation_admission":"REFUSE"}),
        )?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    let mut extra = [0u8; 1];
    if finished && std::io::Read::read(&mut input, &mut extra)? == 0 {
        Ok(())
    } else {
        Err("frame count exceeded or missing terminal EOF".into())
    }
}
// Independent process canary, not an observation-completeness issuer.
fn runtime_probe() -> Result<(), Box<dyn std::error::Error>> {
    let maps = std::fs::read_to_string("/proc/self/maps")?;
    let cmdline = std::fs::read_to_string("/proc/cmdline")?;
    let auxiliary_vdso = unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) };
    let mappings: Vec<_> = maps
        .lines()
        .filter(|line| line.contains("[vdso]") || line.contains("[vvar"))
        .map(str::to_owned)
        .collect();
    #[cfg(target_arch = "x86_64")]
    let has_rdrand = std::is_x86_feature_detected!("rdrand");
    let policy = controller_guard::install()?;
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let syscall_clock =
        unsafe { libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_MONOTONIC, &mut ts) };
    let syscall_errno = io::Error::last_os_error().raw_os_error();
    // libc may use vDSO. Do not substitute a normalized syscall error.
    let libc_clock = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    let libc_errno = if libc_clock < 0 {
        io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    let mut instructions = serde_json::Map::new();
    #[cfg(target_arch = "x86_64")]
    {
        let (lo, hi): (u32, u32);
        unsafe {
            std::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        }
        instructions.insert(
            "rdtsc".into(),
            json!({"observed":((hi as u64)<<32)|lo as u64}),
        );
        if has_rdrand {
            let value: u64;
            let success: u8;
            unsafe {
                std::arch::asm!("rdrand {value}", "setc {success}",
                value=out(reg) value, success=out(reg_byte) success, options(nomem, nostack));
            }
            instructions.insert("rdrand".into(), json!({"success":success,"value":value}));
        } else {
            instructions.insert("rdrand".into(), json!({"status":"UNSUPPORTED"}));
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let value: u64;
        unsafe {
            std::arch::asm!("mrs {value}, cntvct_el0", value=out(reg) value, options(nomem, nostack));
        }
        instructions.insert("cntvct_el0".into(), json!({"observed":value}));
    }
    let body = json!({"schema":"realm.native-observation-canary.v1", "authority":"NONE",
        "complete_observation_admission":"REFUSE", "architecture":std::env::consts::ARCH,
        "boot_cmdline":cmdline, "auxiliary_vdso":auxiliary_vdso,"runtime_mappings":mappings,
        "vdso_absent_observed":auxiliary_vdso == 0 && mappings.is_empty(),
        "syscall_clock":{"return":syscall_clock,"errno":syscall_errno},
        "libc_clock":{"return":libc_clock,"errno":libc_errno,"seconds":ts.tv_sec,"nanoseconds":ts.tv_nsec},
        "direct_instructions":instructions,"syscall_policy_root":policy});
    println!("{}", serde_json::to_string(&body)?);
    Ok(())
}
fn probe(path: &str, alias: &str, inherited_fd: i32) -> Result<(), Box<dyn std::error::Error>> {
    let path = CString::new(path)?;
    let alias = CString::new(alias)?;
    if inherited_fd < 3 {
        return Err("probe descriptor must be outside stdio".into());
    }
    let inherited_before = unsafe { libc::fcntl(inherited_fd, libc::F_GETFD) } >= 0;
    let root = controller_guard::install()?;
    let mut rows = serde_json::Map::new();
    fn record(rows: &mut serde_json::Map<String, serde_json::Value>, key: &str, value: i64) {
        rows.insert(key.into(), json!({"return":value,"errno":if value < 0 {io::Error::last_os_error().raw_os_error()} else {None}}));
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let mut bytes = [0u8; 64];
    unsafe {
        record(
            &mut rows,
            "stat",
            libc::fstatat(libc::AT_FDCWD, path.as_ptr(), stat.as_mut_ptr(), 0) as i64,
        );
        record(
            &mut rows,
            "open",
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::O_RDONLY,
            ) as i64,
        );
        record(
            &mut rows,
            "alias",
            libc::open(alias.as_ptr(), libc::O_RDONLY) as i64,
        );
        record(
            &mut rows,
            "readlink",
            libc::readlink(alias.as_ptr(), bytes.as_mut_ptr().cast(), 64) as i64,
        );
        record(
            &mut rows,
            "getdents",
            libc::syscall(libc::SYS_getdents64, 3, bytes.as_mut_ptr(), 64) as i64,
        );
        record(
            &mut rows,
            "inherited_read",
            libc::read(inherited_fd, bytes.as_mut_ptr().cast(), 1) as i64,
        );
        record(
            &mut rows,
            "socket",
            libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) as i64,
        );
        record(
            &mut rows,
            "execve",
            libc::syscall(libc::SYS_execve, 0, 0, 0) as i64,
        );
        record(
            &mut rows,
            "clone",
            libc::syscall(libc::SYS_clone, 0, 0, 0, 0, 0) as i64,
        );
        record(
            &mut rows,
            "getrandom",
            libc::syscall(libc::SYS_getrandom, bytes.as_mut_ptr(), 1, 0) as i64,
        );
        let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
        record(
            &mut rows,
            "clock_syscall",
            libc::syscall(
                libc::SYS_clock_gettime,
                libc::CLOCK_REALTIME,
                ts.as_mut_ptr(),
            ) as i64,
        );
    }
    // Deliberately expose the limitation: libc can read vDSO time without
    // entering the kernel. This must never become a complete-history proof.
    let vdso_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|v| v.as_nanos().to_string());
    println!(
        "{}",
        json!({"policy_root":root,"observations":rows,"vdso_time":vdso_time,"inherited_before":inherited_before,
        "authority":"NONE","complete_observation_admission":"REFUSE"})
    );
    Ok(())
}
