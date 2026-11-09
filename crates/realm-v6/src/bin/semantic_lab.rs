//! Local consistency laboratory. No output from this tool grants admission.
use realm_v6::{Receipt, Segment, seal_event, seal_segment, validate_receipt, world_root};
use std::io::{self, Read};
fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw).unwrap();
    let values: Vec<serde_json::Value> =
        serde_json::from_value(realm_v6::strict_json::parse(raw.as_bytes()).unwrap()).unwrap();
    if mode.ends_with("v2") {
        let results: Vec<serde_json::Value> = values.into_iter().map(|value| {
            use realm_v6::semantic_v2 as v2;
            if mode == "range-v2" {
                let input: v2::Input = serde_json::from_value(value["input"].clone()).unwrap();
                let current: v2::World = serde_json::from_value(value["current"].clone()).unwrap();
                let verified = v2::validate(&input.receipt, &input.expected).unwrap();
                serde_json::json!({"ranges_match":verified.ranges_match(&current),"admission":"UNAVAILABLE"})
            } else if mode == "check-v2" {
                match serde_json::from_value::<v2::Input>(value) {
                    Ok(input) => match v2::validate(&input.receipt, &input.expected) {
                        Ok(_) => serde_json::json!({"local":"LOCAL_VALID","admission":v2::admit(&input.receipt,&input.expected)}),
                        Err(reason) => serde_json::json!({"local":"REJECT","reason":reason}),
                    },
                    Err(_) => serde_json::json!({"local":"REJECT","reason":"MALFORMED"}),
                }
            } else {
                let mut receipt: v2::Receipt = serde_json::from_value(value).unwrap();
                if mode == "derive-v2" { receipt.dependencies = v2::derive(&receipt).unwrap(); }
                v2::seal(&mut receipt).unwrap();
                serde_json::to_value(receipt).unwrap()
            }
        }).collect();
        println!("{}", serde_json::to_string(&results).unwrap());
        return;
    }
    let results: Vec<serde_json::Value> = values.into_iter().map(|value| {
        let mut receipt: Receipt = serde_json::from_value(value).unwrap();
        if mode == "seal-v1" {
            receipt.bindings.starting_state = world_root(&receipt.starting_world).unwrap();
            receipt.final_world_root = world_root(&receipt.final_world).unwrap();
            let mut previous = "0".repeat(64);
            for event in &mut receipt.ordered_effects {
                event.previous_hash = previous;
                *event = seal_event(event.clone()).unwrap();
                previous = event.hash.clone();
            }
            receipt.effect_root = previous;
            let segment = seal_segment(Segment {sequence: 0, first_event: 0,
                event_count: receipt.ordered_effects.len() as u64, lost_events: 0,
                previous_hash: "0".repeat(64), hash: String::new()}, &receipt.ordered_effects).unwrap();
            receipt.segment_root = segment.hash.clone(); receipt.segments = vec![segment];
            serde_json::to_value(receipt).unwrap()
        } else if mode == "check-v1" {
            match validate_receipt(&receipt) {
                Ok(_) => serde_json::json!({"local": "LOCAL_VALID", "admission": "UNAVAILABLE"}),
                Err(reason) => serde_json::json!({"local": "REJECT", "reason": reason, "admission": "UNAVAILABLE"}),
            }
        } else { panic!("usage: semantic_lab seal-v1|check-v1"); }
    }).collect();
    println!("{}", serde_json::to_string(&results).unwrap());
}
