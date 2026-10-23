//! Reject duplicate keys at every nesting level before typed deserialization.
use crate::Refusal;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use std::fmt;
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON with unique object keys and integer numbers")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(Value::Number(Number::from(v))))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(Value::Number(Number::from(v))))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Strict, E> {
                Ok(Strict(Value::String(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut result = Vec::new();
                while let Some(Strict(value)) = seq.next_element()? {
                    result.push(value);
                }
                Ok(Strict(Value::Array(result)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut result = Map::new();
                while let Some((key, Strict(value))) = map.next_entry::<String, Strict>()? {
                    if result.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                }
                Ok(Strict(Value::Object(result)))
            }
        }
        d.deserialize_any(V)
    }
}
pub fn parse(bytes: &[u8]) -> Result<Value, Refusal> {
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(Refusal::ResourceLimit);
    }
    serde_json::from_slice::<Strict>(bytes)
        .map(|v| v.0)
        .map_err(|_| Refusal::Malformed)
}

/// Nullable is not optional: missing wire fields must be rejected by Serde.
pub fn present_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

pub fn unique_strings<'de, D>(
    deserializer: D,
) -> Result<std::collections::BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    let count = values.len();
    let result: std::collections::BTreeSet<String> = values.into_iter().collect();
    if count != result.len() {
        return Err(de::Error::custom("duplicate set entry"));
    }
    Ok(result)
}
