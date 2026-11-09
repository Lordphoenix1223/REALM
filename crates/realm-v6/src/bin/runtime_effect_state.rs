#[cfg(unix)]
fn main() {
    use realm_v6::runtime_effects::{EffectRequest, RuntimeEffectBroker, initialize_counter};
    let args = std::env::args().collect::<Vec<_>>();
    let action = args.get(1).map(String::as_str).unwrap_or("");
    let path = std::path::Path::new(args.get(2).map(String::as_str).unwrap_or(""));
    let result = (|| -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        if action == "init-counter" {
            initialize_counter(path)?;
            return Ok(serde_json::json!({"seed":"counter=0","authority":"NON_AUTHORIZING"}));
        }
        let mut broker = RuntimeEffectBroker::reopen(path)?;
        let report = match action {
            "inspect" => broker.report()?,
            "ack" => broker.acknowledge()?,
            "retry-effect" => {
                let request: EffectRequest = serde_json::from_reader(std::io::stdin().lock())?;
                broker.recover_requested(request)?
            }
            _ => {
                return Err(
                    "usage: runtime_effect_state init-counter|inspect|ack|retry-effect PATH".into(),
                );
            }
        };
        Ok(serde_json::to_value(report)?)
    })();
    match result {
        Ok(value) => println!("{value}"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    }
}
#[cfg(not(unix))]
fn main() {
    std::process::exit(69);
}
