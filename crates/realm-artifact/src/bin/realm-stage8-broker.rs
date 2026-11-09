//! Trusted Stage 8 protocol endpoint. This process is NOT the sandboxed executor.
//! Its stdio must be owned by a trusted, bounded sandbox supervisor.
use realm_artifact::host_apply::{
    self, coding_transfer,
    ordered_create::stage8::{self, Session},
};
use std::{
    io::{self, BufRead, Write},
    path::Path,
};

fn frame(input: &mut impl BufRead) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    // Bounded before allocation, including a malicious nonterminated frame.
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            break;
        }
        let n = available
            .iter()
            .position(|c| *c == b'\n')
            .map_or(available.len(), |i| i + 1);
        if bytes.len() + n > stage8::MAX_FRAME {
            return Err("REFUSE: frame byte budget".into());
        }
        bytes.extend_from_slice(&available[..n]);
        input.consume(n);
        if bytes.ends_with(b"\n") {
            break;
        }
    }
    Ok(bytes)
}
fn print(value: impl serde::Serialize) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string(&value)?);
    io::stdout().flush()?;
    Ok(())
}
fn read(path: &str) -> host_apply::Result<Vec<u8>> {
    host_apply::read_transfer_file(Path::new(path))
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mut session = match args.as_slice() {
        [c] if c == "hash-stdin" => {
            let mut bytes = Vec::new();
            io::stdin().take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 2 * 1024 * 1024 { return Err("hash byte budget".into()); }
            println!("{}", blake3::hash(&bytes).to_hex()); return Ok(());
        }
        [c, file] if c == "hash" => { println!("{}", blake3::hash(&read(file)?).to_hex()); return Ok(()); }
        [c, file, proof, policy, destination, state] if c == "production" => {
            Session::verified_transfer(&read(file)?, &coding_transfer::strict_json(&read(proof)?)?,
                &coding_transfer::strict_json(&read(policy)?)?, Path::new(destination), Path::new(state))?
        }
        [c, file, pin, expectations, ep, procedure_pin, parent] if c == "disposable-procedure" => {
            #[cfg(feature = "receiver-fixtures")]
            { Session::disposable_procedure(&read(file)?, pin, &read(expectations)?, ep, procedure_pin, Path::new(parent))? }
            #[cfg(not(feature = "receiver-fixtures"))]
            { let _ = (file, pin, expectations, ep, procedure_pin, parent); return Err("REFUSE: disposable Stage 8 absent; receiver-fixtures required".into()); }
        }
        [c, file, pin, expectations, ep, parent] if c == "disposable-development" => {
            #[cfg(feature = "receiver-fixtures")]
            { Session::disposable_capture(&read(file)?, pin, &read(expectations)?, ep, Path::new(parent))? }
            #[cfg(not(feature = "receiver-fixtures"))]
            { let _ = (file, pin, expectations, ep, parent); return Err("REFUSE: disposable Stage 8 absent; receiver-fixtures required".into()); }
        }
        _ => return Err("usage: realm-stage8-broker hash FILE | production FILE PROOF POLICY DEST STATE | disposable-development FILE PIN EXPECTATIONS EXPECTATIONS_PIN PRIVATE_PARENT | disposable-procedure FILE PIN EXPECTATIONS EXPECTATIONS_PIN PROCEDURE_PIN PRIVATE_PARENT".into()),
    };
    print(
        serde_json::json!({"status":"PREPARED_REQUIRES_INDEPENDENT_GRANT", "plan":session.plan(),
        "destination":session.destination(), "state":session.state(), "grant_proposal":session.grant_proposal()?}),
    )?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let grant = frame(&mut input)?;
    session.activate(coding_transfer::strict_json(&grant)?)?;
    print(serde_json::json!({"status":"ACTIVE"}))?;
    // Allow an extra refused request to be recorded, but bound hostile traffic.
    for _ in 0..16 {
        let request = frame(&mut input)?;
        if request.is_empty() {
            break;
        }
        print(session.dispatch(&request))?;
    }
    // EOF is owned by the trusted supervisor. There is no executor-accessible
    // magic command that can bypass the exact request gate.
    match session.verify() {
        Ok(report) => print(report)?,
        Err(e) => print(serde_json::json!({"status":"INCOMPLETE", "error":e.to_string()}))?,
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("realm-stage8-broker: {e}");
        std::process::exit(1);
    }
}
