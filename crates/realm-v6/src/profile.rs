//! Optional diagnostic timing. It is never an admission or publication input.
//! Durations include nested scopes; overlapping timings must not be summed.
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
static TRACE: OnceLock<Mutex<File>> = OnceLock::new();
static EPOCH: OnceLock<Instant> = OnceLock::new();
static NEXT_SPAN: AtomicU64 = AtomicU64::new(1);
thread_local! { static STACK:std::cell::RefCell<Vec<u64>>=const {std::cell::RefCell::new(Vec::new())}; }
/// Call only with the already validated private evidence directory outside S0/S1.
/// Failure affects diagnostics only. The caller records the failure explicitly.
pub fn initialize(evidence: &Path) -> io::Result<()> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    o.mode(0o600);
    let f = o.open(evidence.join("pipeline-profile.jsonl"))?;
    TRACE
        .set(Mutex::new(f))
        .map_err(|_| io::Error::other("profile already initialized"))?;
    EPOCH.get_or_init(Instant::now);
    emit(
        serde_json::json!({"kind":"metadata","schema":"realm.v6.pipeline-profile/v1","inclusive_scopes":true,"authority":false,"cpu_scope":"process plus reaped child CPU; concurrent scopes overlap"}),
    );
    Ok(())
}
fn emit(mut x: serde_json::Value) {
    let Some(trace) = TRACE.get() else { return };
    x["pid"] = std::process::id().into();
    x["elapsed_seconds"] = EPOCH
        .get_or_init(Instant::now)
        .elapsed()
        .as_secs_f64()
        .into();
    if let Ok(mut f) = trace.lock() {
        let _ = serde_json::to_writer(&mut *f, &x);
        let _ = f.write_all(b"\n");
    }
}
#[cfg(unix)]
fn cpu() -> f64 {
    let mut total = 0.;
    for who in [libc::RUSAGE_SELF, libc::RUSAGE_CHILDREN] {
        let mut r = std::mem::MaybeUninit::<libc::rusage>::uninit();
        if unsafe { libc::getrusage(who, r.as_mut_ptr()) } == 0 {
            let r = unsafe { r.assume_init() };
            total += r.ru_utime.tv_sec as f64
                + r.ru_utime.tv_usec as f64 / 1e6
                + r.ru_stime.tv_sec as f64
                + r.ru_stime.tv_usec as f64 / 1e6;
        }
    }
    total
}
#[cfg(not(unix))]
fn cpu() -> f64 {
    0.
}
/// RAII timing preserves the original operation, including early errors.
pub struct Span {
    stage: &'static str,
    start: Option<(Instant, f64)>,
    id: u64,
    parent: Option<u64>,
}
impl Span {
    pub fn new(stage: &'static str) -> Self {
        let start = TRACE.get().map(|_| (Instant::now(), cpu()));
        let id = NEXT_SPAN.fetch_add(1, Ordering::Relaxed);
        let parent = STACK.with(|s| s.borrow().last().copied());
        if start.is_some() {
            STACK.with(|s| s.borrow_mut().push(id));
            emit(
                serde_json::json!({"kind":"begin","stage":stage,"span_id":id,"parent_span_id":parent,"thread":format!("{:?}",std::thread::current().id())}),
            );
        }
        Self {
            stage,
            start,
            id,
            parent,
        }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if let Some((w, c)) = self.start {
            STACK.with(|s| s.borrow_mut().retain(|id| *id != self.id));
            emit(
                serde_json::json!({"kind":"end","stage":self.stage,"span_id":self.id,"parent_span_id":self.parent,"wall_seconds":w.elapsed().as_secs_f64(),"cpu_seconds":(cpu()-c).max(0.)}),
            );
        }
    }
}
pub fn bytes(stage: &'static str, operation: &'static str, bytes: u64) {
    if TRACE.get().is_some() {
        emit(serde_json::json!({"kind":"bytes","stage":stage,"operation":operation,"bytes":bytes}));
    }
}
/// Same syscall and error propagation; diagnostics count successful barriers.
pub trait SyncTrace {
    fn sync_all_traced(&self) -> io::Result<()>;
    fn sync_data_traced(&self) -> io::Result<()>;
}
impl SyncTrace for File {
    fn sync_all_traced(&self) -> io::Result<()> {
        let _s = Span::new("durability_fsync");
        let r = self.sync_all();
        if r.is_ok() {
            emit(serde_json::json!({"kind":"barrier","operation":"fsync"}));
        }
        r
    }
    fn sync_data_traced(&self) -> io::Result<()> {
        let _s = Span::new("durability_fdatasync");
        let r = self.sync_data();
        if r.is_ok() {
            emit(serde_json::json!({"kind":"barrier","operation":"fdatasync"}));
        }
        r
    }
}
