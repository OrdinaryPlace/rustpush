// Modified 2026-10-27 for OrdinaryPlace Buddy. Licensed under this repository's
// SSPL v1; see LICENSE and LICENSE.exceptions. Independently implemented from
// the public native-poll JSON shape documented by sbaresearch/transcript-consistency
// at cc89bf6d418aa3c78b0366e5c80b19dc364aa020. See docs/native-polls.md.
//! Offline native Apple Polls data-URL codec. This module performs no I/O.
//!
//! Creator and participant handles are untrusted payload claims. Applications
//! must bind them to the authenticated `MessageInst.sender` and verified aliases
//! before using them as identities. A decoded vote is not an authenticated vote.
//! This codec does not construct a balloon, send a message, or tally results.
//! Actual balloon/message construction and correlated receive extraction live
//! on `NormalMessage`, `ReactMessage`, and `MessageInst` in `messages.rs`.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::{self, Write};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const POLLS_BUNDLE_ID: &str =
    "com.apple.messages.MSMessageExtensionBalloonPlugin:0000000000:com.apple.messages.Polls";
pub const PAYLOAD_VERSION: u32 = 1;
// Local resource limits, not claimed native protocol limits.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_DATA_URL_BYTES: usize = 6 + ((MAX_PAYLOAD_BYTES + 2) / 3) * 4 + 1024;
const DATA_URL_PREFIX: &str = "data:,";

/// Errors intentionally contain no source URL, JSON, handles, or option text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    DataUrlTooLarge,
    PayloadTooLarge,
    InvalidDataUrl,
    InvalidBase64,
    InvalidJson,
    DuplicateKeys,
    InvalidShape,
    UnsupportedVersion,
    InvalidOutboundPoll,
    InvalidOutboundVote,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DataUrlTooLarge => "Poll data URL exceeds the local size limit",
            Self::PayloadTooLarge => "Poll payload exceeds the local size limit",
            Self::InvalidDataUrl => "Invalid poll data URL",
            Self::InvalidBase64 => "Invalid poll payload encoding",
            Self::InvalidJson => "Invalid poll payload JSON",
            Self::DuplicateKeys => "Duplicate object keys in poll payload",
            Self::InvalidShape => "Invalid or ambiguous poll payload shape",
            Self::UnsupportedVersion => "Unsupported poll payload version",
            Self::InvalidOutboundPoll => "Invalid new poll",
            Self::InvalidOutboundVote => "Invalid new poll vote",
        })
    }
}

impl std::error::Error for CodecError {}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PollOption {
    pub text: String,
    pub can_be_edited: bool,
    pub option_identifier: String,
    /// Untrusted payload claim, not an authenticated account identity.
    pub creator_handle: String,
    pub attributed_text: String,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PollItem {
    pub ordered_poll_options: Vec<PollOption>,
    /// Native inbound titles may be empty; a caption can be a separate message.
    pub title: String,
    /// Untrusted payload claim, not an authenticated account identity.
    pub creator_handle: String,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PollPayload {
    pub item: PollItem,
    pub version: u32,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl PollPayload {
    /// Construct a new poll using caller-provided stable option IDs. Identifiers,
    /// text, and handle case are preserved without normalization. The caller
    /// supplies IDs so retries can reuse a persisted operation, not mint new IDs.
    /// This codec checks nonempty unique strings, not native UUID validity. The
    /// transport adapter must generate and persist native option/session UUIDs.
    pub fn new(
        creator_handle: String,
        title: String,
        options: Vec<(String, String)>,
    ) -> Result<Self, CodecError> {
        if creator_handle.is_empty() || !(2..=12).contains(&options.len()) {
            return Err(CodecError::InvalidOutboundPoll);
        }
        let mut identifiers = HashSet::new();
        let mut ordered_poll_options = Vec::with_capacity(options.len());
        for (option_identifier, text) in options {
            if option_identifier.is_empty() || text.is_empty() || !identifiers.insert(option_identifier.clone()) {
                return Err(CodecError::InvalidOutboundPoll);
            }
            ordered_poll_options.push(PollOption {
                attributed_text: text.clone(),
                text,
                can_be_edited: false,
                option_identifier,
                creator_handle: creator_handle.clone(),
                extra: BTreeMap::new(),
            });
        }
        let result = Self {
            item: PollItem { ordered_poll_options, title, creator_handle, extra: BTreeMap::new() },
            version: PAYLOAD_VERSION,
            extra: BTreeMap::new(),
        };
        bounded_json(&NativePollPayload::Poll(result.clone()))?;
        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PollVote {
    /// Untrusted payload claim. Never count a vote using this field alone.
    pub participant_handle: String,
    pub vote_option_identifier: String,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PollVoteItem {
    /// Empty inbound lists are preserved. No unvote meaning is inferred here.
    pub votes: Vec<PollVote>,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PollVotePayload {
    pub item: PollVoteItem,
    pub version: u32,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl PollVotePayload {
    /// Construct explicit selections only. Empty inbound lists can still be
    /// decoded and re-encoded; this constructor does not invent an unvote API.
    pub fn new(selections: Vec<(String, String)>) -> Result<Self, CodecError> {
        if selections.is_empty() {
            return Err(CodecError::InvalidOutboundVote);
        }
        let mut seen = HashSet::new();
        let mut votes = Vec::with_capacity(selections.len());
        for (participant_handle, vote_option_identifier) in selections {
            if participant_handle.is_empty() || vote_option_identifier.is_empty()
                || !seen.insert((participant_handle.clone(), vote_option_identifier.clone())) {
                return Err(CodecError::InvalidOutboundVote);
            }
            votes.push(PollVote { participant_handle, vote_option_identifier, extra: BTreeMap::new() });
        }
        let result = Self {
            item: PollVoteItem { votes, extra: BTreeMap::new() },
            version: PAYLOAD_VERSION,
            extra: BTreeMap::new(),
        };
        bounded_json(&NativePollPayload::Vote(result.clone()))?;
        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum NativePollPayload {
    Poll(PollPayload),
    Vote(PollVotePayload),
}

/// Preserve optional data-URL query metadata without treating it as authority.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedDataUrl {
    pub payload: NativePollPayload,
    pub query: Option<String>,
}

impl DecodedDataUrl {
    /// Re-encode the represented inbound shape, including unknown JSON fields
    /// and query metadata. This does not apply new-poll constructor constraints.
    pub fn encode(&self) -> Result<String, CodecError> {
        encode_with_query(&self.payload, self.query.as_deref())
    }
}

/// Decode only the documented base64 JSON data-URL shape. No URL is fetched.
/// The caller must first identify the native Polls bundle and bind the balloon
/// session, original message GUID, conversation, and authenticated sender.
pub fn decode_data_url(url: &str) -> Result<DecodedDataUrl, CodecError> {
    if url.len() > MAX_DATA_URL_BYTES {
        return Err(CodecError::DataUrlTooLarge);
    }
    let data = url.strip_prefix(DATA_URL_PREFIX).ok_or(CodecError::InvalidDataUrl)?;
    let (encoded, query) = match data.split_once('?') {
        Some((encoded, query)) => (encoded, Some(query.to_string())),
        None => (data, None),
    };
    let bytes = STANDARD.decode(encoded).map_err(|_| CodecError::InvalidBase64)?;
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(CodecError::PayloadTooLarge);
    }
    reject_duplicate_keys(&bytes)?;
    let shape: Value = serde_json::from_slice(&bytes).map_err(|_| CodecError::InvalidJson)?;
    let version = shape.get("version").and_then(Value::as_u64).ok_or(CodecError::InvalidShape)?;
    if version != u64::from(PAYLOAD_VERSION) {
        return Err(CodecError::UnsupportedVersion);
    }
    let item = shape.get("item").and_then(Value::as_object).ok_or(CodecError::InvalidShape)?;
    let payload = match (item.contains_key("orderedPollOptions"), item.contains_key("votes")) {
        (true, false) => NativePollPayload::Poll(
            serde_json::from_slice(&bytes).map_err(|_| CodecError::InvalidShape)?),
        (false, true) => NativePollPayload::Vote(
            serde_json::from_slice(&bytes).map_err(|_| CodecError::InvalidShape)?),
        _ => return Err(CodecError::InvalidShape),
    };
    Ok(DecodedDataUrl { payload, query })
}

/// Canonical envelope for a represented payload. New polls use the observed
/// `src=p&c=2` query; votes have none. Use constructors for new outbound data.
pub fn encode_data_url(payload: &NativePollPayload) -> Result<String, CodecError> {
    let query = match payload {
        NativePollPayload::Poll(_) => Some("src=p&c=2"),
        NativePollPayload::Vote(_) => None,
    };
    encode_with_query(payload, query)
}

fn encode_with_query(payload: &NativePollPayload, query: Option<&str>) -> Result<String, CodecError> {
    let bytes = bounded_json(payload)?;
    let mut url = format!("{}{}", DATA_URL_PREFIX, STANDARD.encode(bytes));
    if let Some(query) = query {
        // Check before copying caller-provided metadata into the output.
        if query.len() > MAX_DATA_URL_BYTES.saturating_sub(url.len() + 1) {
            return Err(CodecError::DataUrlTooLarge);
        }
        url.push('?');
        url.push_str(query);
    }
    if url.len() > MAX_DATA_URL_BYTES {
        return Err(CodecError::DataUrlTooLarge);
    }
    Ok(url)
}

fn reserved(extra: &BTreeMap<String, Value>, keys: &[&str]) -> bool {
    keys.iter().any(|key| extra.contains_key(*key))
}

// Validate before constructing Value/maps: those representations would silently
// overwrite duplicate keys, including unknown nested fields. Keep one key set
// per object, recurse through arrays, and discard scalars without retaining them.
// The serde_json deserializer's normal recursion limit remains enabled.
struct UniqueKeysSeed<'a> {
    duplicate_found: &'a mut bool,
}

struct UniqueKeysVisitor<'a> {
    duplicate_found: &'a mut bool,
}

impl<'de> DeserializeSeed<'de> for UniqueKeysSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where D: de::Deserializer<'de> {
        deserializer.deserialize_any(UniqueKeysVisitor { duplicate_found: self.duplicate_found })
    }
}

impl<'de> Visitor<'de> for UniqueKeysVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON with unique object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<(), E> { Ok(()) }
    fn visit_i64<E>(self, _value: i64) -> Result<(), E> { Ok(()) }
    fn visit_u64<E>(self, _value: u64) -> Result<(), E> { Ok(()) }
    fn visit_f64<E>(self, _value: f64) -> Result<(), E> { Ok(()) }
    fn visit_str<E>(self, _value: &str) -> Result<(), E> { Ok(()) }
    fn visit_string<E>(self, _value: String) -> Result<(), E> { Ok(()) }
    fn visit_unit<E>(self) -> Result<(), E> { Ok(()) }

    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where A: SeqAccess<'de> {
        while sequence.next_element_seed(UniqueKeysSeed { duplicate_found: &mut *self.duplicate_found })?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut object: A) -> Result<(), A::Error>
    where A: MapAccess<'de> {
        let mut keys = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key) {
                *self.duplicate_found = true;
                return Err(de::Error::custom("Duplicate JSON object key"));
            }
            object.next_value_seed(UniqueKeysSeed { duplicate_found: &mut *self.duplicate_found })?;
        }
        Ok(())
    }
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), CodecError> {
    let mut duplicate_found = false;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let result = UniqueKeysSeed { duplicate_found: &mut duplicate_found }.deserialize(&mut deserializer);
    if result.is_err() {
        return Err(if duplicate_found { CodecError::DuplicateKeys } else { CodecError::InvalidJson });
    }
    deserializer.end().map_err(|_| CodecError::InvalidJson)
}

fn validate_representation(payload: &NativePollPayload) -> Result<(), CodecError> {
    let (version, extra) = match payload {
        NativePollPayload::Poll(poll) => {
            if reserved(&poll.item.extra, &["orderedPollOptions", "title", "creatorHandle", "votes"])
                || poll.item.ordered_poll_options.iter().any(|option| reserved(&option.extra,
                    &["text", "canBeEdited", "optionIdentifier", "creatorHandle", "attributedText"])) {
                return Err(CodecError::InvalidShape);
            }
            (poll.version, &poll.extra)
        }
        NativePollPayload::Vote(vote) => {
            if reserved(&vote.item.extra, &["votes", "orderedPollOptions"])
                || vote.item.votes.iter().any(|entry| reserved(&entry.extra,
                    &["participantHandle", "voteOptionIdentifier"])) {
                return Err(CodecError::InvalidShape);
            }
            (vote.version, &vote.extra)
        }
    };
    if version != PAYLOAD_VERSION {
        return Err(CodecError::UnsupportedVersion);
    }
    if reserved(extra, &["version", "item"]) {
        return Err(CodecError::InvalidShape);
    }
    Ok(())
}

struct LimitedWriter {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_PAYLOAD_BYTES.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::new(io::ErrorKind::Other, "Poll payload size limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_json(payload: &NativePollPayload) -> Result<Vec<u8>, CodecError> {
    validate_representation(payload)?;
    let mut writer = LimitedWriter { bytes: Vec::new(), exceeded: false };
    let result = match payload {
        NativePollPayload::Poll(poll) => serde_json::to_writer(&mut writer, poll),
        NativePollPayload::Vote(vote) => serde_json::to_writer(&mut writer, vote),
    };
    if result.is_err() {
        return Err(if writer.exceeded { CodecError::PayloadTooLarge } else { CodecError::InvalidShape });
    }
    Ok(writer.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn data_url(value: Value) -> String {
        format!("data:,{}", STANDARD.encode(serde_json::to_vec(&value).unwrap()))
    }

    fn poll_json() -> Value {
        json!({"version":1,"item":{"title":"Dinner?","creatorHandle":"Buddy@Example.test",
            "orderedPollOptions":[
                {"text":"Pizza","canBeEdited":false,"optionIdentifier":"OPT-A","creatorHandle":"Buddy@Example.test","attributedText":"Pizza"},
                {"text":"Sushi","canBeEdited":false,"optionIdentifier":"OPT-b","creatorHandle":"Buddy@Example.test","attributedText":"Sushi"}]}})
    }

    fn vote_json(votes: Value) -> Value {
        json!({"version":1,"item":{"votes":votes}})
    }

    #[test]
    fn native_poll_fixture_decodes_without_losing_case_order_or_ids() {
        let decoded = decode_data_url(&(data_url(poll_json()) + "?src=p&c=2")).unwrap();
        let NativePollPayload::Poll(poll) = &decoded.payload else { panic!("Expected poll") };
        assert_eq!(poll.item.title, "Dinner?");
        assert_eq!(poll.item.creator_handle, "Buddy@Example.test");
        assert_eq!(poll.item.ordered_poll_options[0].option_identifier, "OPT-A");
        assert_eq!(poll.item.ordered_poll_options[1].option_identifier, "OPT-b");
        assert_eq!(decoded.query.as_deref(), Some("src=p&c=2"));
        assert_eq!(decode_data_url(&decoded.encode().unwrap()).unwrap(), decoded);
    }

    #[test]
    fn new_poll_has_native_fields_and_canonical_query() {
        let poll = PollPayload::new("mailto:Buddy@Example.test".into(), "選ぶ 🍣".into(),
            vec![("ID-1".into(), "寿司".into()), ("id-2".into(), "Pizza".into())]).unwrap();
        assert_eq!(poll.item.ordered_poll_options[0].attributed_text, "寿司");
        assert_eq!(poll.item.creator_handle, "mailto:Buddy@Example.test");
        let payload = NativePollPayload::Poll(poll);
        let url = encode_data_url(&payload).unwrap();
        assert!(url.ends_with("?src=p&c=2"));
        assert_eq!(decode_data_url(&url).unwrap().payload, payload);
    }

    #[test]
    fn unknown_fields_and_query_metadata_survive_round_trip() {
        let mut value = poll_json();
        value["futureEnvelope"] = json!({"flag":true});
        value["item"]["futureItem"] = json!([1, 2]);
        value["item"]["orderedPollOptions"][0]["futureOption"] = json!("retained");
        let decoded = decode_data_url(&(data_url(value) + "?src=p&c=2&future=x")).unwrap();
        assert_eq!(decode_data_url(&decoded.encode().unwrap()).unwrap(), decoded);
        let NativePollPayload::Poll(poll) = decoded.payload else { panic!("Expected poll") };
        assert_eq!(poll.extra["futureEnvelope"], json!({"flag":true}));
        assert_eq!(poll.item.extra["futureItem"], json!([1, 2]));
        assert_eq!(poll.item.ordered_poll_options[0].extra["futureOption"], "retained");
    }

    #[test]
    fn inbound_unusual_values_are_preserved_without_outbound_inferences() {
        let mut value = poll_json();
        value["item"]["title"] = json!("");
        value["item"]["orderedPollOptions"] = json!([]);
        let decoded = decode_data_url(&data_url(value)).unwrap();
        let NativePollPayload::Poll(poll) = &decoded.payload else { panic!("Expected poll") };
        assert!(poll.item.title.is_empty());
        assert!(poll.item.ordered_poll_options.is_empty());
        assert_eq!(decode_data_url(&decoded.encode().unwrap()).unwrap(), decoded);
        let empty = decode_data_url(&data_url(vote_json(json!([])))).unwrap();
        let NativePollPayload::Vote(vote) = &empty.payload else { panic!("Expected vote") };
        assert!(vote.item.votes.is_empty());
        assert_eq!(decode_data_url(&empty.encode().unwrap()).unwrap(), empty);
    }

    #[test]
    fn native_vote_fixture_keeps_each_untrusted_claim_and_unknown_field() {
        let value = vote_json(json!([
            {"participantHandle":"One@Example.test","voteOptionIdentifier":"OPT-A","future":1},
            {"participantHandle":"Other@Example.test","voteOptionIdentifier":"OPT-b"}]));
        let decoded = decode_data_url(&data_url(value)).unwrap();
        let NativePollPayload::Vote(vote) = &decoded.payload else { panic!("Expected vote") };
        assert_eq!(vote.item.votes.len(), 2);
        assert_eq!(vote.item.votes[0].participant_handle, "One@Example.test");
        assert_eq!(vote.item.votes[1].participant_handle, "Other@Example.test");
        assert_eq!(vote.item.votes[0].extra["future"], 1);
        assert_eq!(decode_data_url(&decoded.encode().unwrap()).unwrap(), decoded);
    }

    #[test]
    fn explicit_vote_constructor_preserves_multiple_selections() {
        let vote = PollVotePayload::new(vec![("Actor@Example.test".into(), "A".into()),
            ("Actor@Example.test".into(), "B".into())]).unwrap();
        let payload = NativePollPayload::Vote(vote);
        let url = encode_data_url(&payload).unwrap();
        assert!(!url.contains('?'));
        assert_eq!(decode_data_url(&url).unwrap().payload, payload);
        assert_eq!(PollVotePayload::new(vec![]), Err(CodecError::InvalidOutboundVote));
        assert_eq!(PollVotePayload::new(vec![("".into(), "A".into())]), Err(CodecError::InvalidOutboundVote));
        assert_eq!(PollVotePayload::new(vec![("actor".into(), "A".into()), ("actor".into(), "A".into())]),
            Err(CodecError::InvalidOutboundVote));
    }

    #[test]
    fn outbound_option_boundaries_and_stable_ids_are_checked() {
        for count in [0, 1, 13] {
            let options = (0..count).map(|i| (format!("ID-{i}"), "choice".into())).collect();
            assert_eq!(PollPayload::new("creator".into(), "title".into(), options), Err(CodecError::InvalidOutboundPoll));
        }
        for count in [2, 12] {
            let options = (0..count).map(|i| (format!("ID-{i}"), "choice".into())).collect();
            assert!(PollPayload::new("creator".into(), "".into(), options).is_ok());
        }
        assert_eq!(PollPayload::new("creator".into(), "title".into(),
            vec![("same".into(), "A".into()), ("same".into(), "B".into())]), Err(CodecError::InvalidOutboundPoll));
        assert_eq!(PollPayload::new("creator".into(), "title".into(),
            vec![("".into(), "A".into()), ("id".into(), "B".into())]), Err(CodecError::InvalidOutboundPoll));
    }

    #[test]
    fn unknown_versions_and_ambiguous_or_malformed_shapes_are_rejected() {
        let mut value = poll_json();
        value["version"] = json!(2);
        assert_eq!(decode_data_url(&data_url(value)), Err(CodecError::UnsupportedVersion));
        let mut value = poll_json();
        value["item"]["votes"] = json!([]);
        assert_eq!(decode_data_url(&data_url(value)), Err(CodecError::InvalidShape));
        for value in [json!({"version":1,"item":{}}), json!({"version":1,"item":{"votes":"wrong"}}),
            json!({"version":"1","item":{"votes":[]}}), json!({"version":1,"item":null}), json!([])] {
            assert_eq!(decode_data_url(&data_url(value)), Err(CodecError::InvalidShape));
        }
    }

    #[test]
    fn duplicate_known_json_keys_and_reserved_extra_fields_are_rejected() {
        let bytes = br#"{"version":1,"version":1,"item":{"votes":[]}}"#;
        let url = format!("data:,{}", STANDARD.encode(bytes));
        assert_eq!(decode_data_url(&url), Err(CodecError::DuplicateKeys));
        let NativePollPayload::Poll(mut poll) = decode_data_url(&data_url(poll_json())).unwrap().payload
            else { panic!("Expected poll") };
        poll.item.extra.insert("votes".into(), json!([]));
        assert_eq!(encode_data_url(&NativePollPayload::Poll(poll)), Err(CodecError::InvalidShape));
    }

    #[test]
    fn duplicate_unknown_keys_are_rejected_at_every_object_depth() {
        // Literal bytes are essential: json! and maps cannot represent a
        // duplicate key and would conceal the regression before the test ran.
        let fixtures: &[&[u8]] = &[
            br#"{"version":1,"item":{"votes":[]},"future":1,"future":2}"#,
            br#"{"version":1,"item":{"votes":[],"future":1,"future":2}}"#,
            br#"{"version":1,"item":{"title":"","creatorHandle":"actor","orderedPollOptions":[{"text":"A","canBeEdited":false,"optionIdentifier":"ID","creatorHandle":"actor","attributedText":"A","future":1,"future":2}]}}"#,
            br#"{"version":1,"item":{"votes":[{"participantHandle":"actor","voteOptionIdentifier":"ID","future":1,"future":2}]}}"#,
            br#"{"version":1,"item":{"votes":[]},"future":{"nested":{"key":1,"key":2}}}"#,
            br#"{"version":1,"item":{"votes":[]},"future":[null,true,1,1.5,"text",[{"key":1,"key":2}]]}"#,
            br#"{"version":1,"item":{"votes":[]},"future":{"key":1,"\u006bey":2}}"#,
        ];
        for bytes in fixtures {
            let url = format!("data:,{}", STANDARD.encode(bytes));
            assert_eq!(decode_data_url(&url), Err(CodecError::DuplicateKeys));
        }
    }

    #[test]
    fn repeated_keys_in_distinct_array_objects_remain_valid_and_preserved() {
        let bytes = br#"{"version":1,"item":{"votes":[]},"future":[{"key":1},{"key":2},[{"key":3}]]}"#;
        let decoded = decode_data_url(&format!("data:,{}", STANDARD.encode(bytes))).unwrap();
        assert_eq!(decode_data_url(&decoded.encode().unwrap()).unwrap(), decoded);
        let NativePollPayload::Vote(vote) = decoded.payload else { panic!("Expected vote") };
        assert_eq!(vote.extra["future"], json!([{"key":1},{"key":2},[{"key":3}]]));
    }

    #[test]
    fn duplicate_key_errors_do_not_expose_key_or_value_content() {
        let bytes = br#"{"version":1,"item":{"votes":[]},"SYNTHETIC-PRIVATE-KEY":"SYNTHETIC-PRIVATE-VALUE","SYNTHETIC-PRIVATE-KEY":null}"#;
        let error = decode_data_url(&format!("data:,{}", STANDARD.encode(bytes))).unwrap_err();
        assert_eq!(error, CodecError::DuplicateKeys);
        assert!(!error.to_string().contains("SYNTHETIC"));
        assert!(!format!("{error:?}").contains("SYNTHETIC"));
    }

    #[test]
    fn malformed_envelopes_fail_without_echoing_private_input() {
        let marker = "SYNTHETIC-PRIVATE-MARKER";
        for url in [format!("https://{marker}"), format!("data:,{marker}!"),
            format!("data:,{}", STANDARD.encode(marker)), "data:,".into(),
            format!("data:application/json;base64,{}", STANDARD.encode(marker))] {
            let error = decode_data_url(&url).unwrap_err();
            assert!(!error.to_string().contains(marker));
            assert!(!format!("{error:?}").contains(marker));
        }
        assert_eq!(decode_data_url("data:,!!!!"), Err(CodecError::InvalidBase64));
        assert_eq!(decode_data_url("data:,ew=="), Err(CodecError::InvalidJson));
        assert_eq!(decode_data_url(&format!("data:,{}", STANDARD.encode([0xff, 0xfe]))), Err(CodecError::InvalidJson));
    }

    #[test]
    fn size_limits_cover_encoded_input_decoded_input_and_serialized_output() {
        assert_eq!(decode_data_url(&"x".repeat(MAX_DATA_URL_BYTES + 1)), Err(CodecError::DataUrlTooLarge));
        let url = format!("data:,{}", STANDARD.encode(vec![b' '; MAX_PAYLOAD_BYTES + 1]));
        assert_eq!(decode_data_url(&url), Err(CodecError::PayloadTooLarge));
        let NativePollPayload::Poll(mut poll) = decode_data_url(&data_url(poll_json())).unwrap().payload
            else { panic!("Expected poll") };
        poll.item.title = "x".repeat(MAX_PAYLOAD_BYTES);
        assert_eq!(encode_data_url(&NativePollPayload::Poll(poll)), Err(CodecError::PayloadTooLarge));
        let mut decoded = decode_data_url(&data_url(vote_json(json!([])))).unwrap();
        decoded.query = Some("x".repeat(MAX_DATA_URL_BYTES));
        assert_eq!(decoded.encode(), Err(CodecError::DataUrlTooLarge));
    }

    #[test]
    fn payload_byte_boundary_is_inclusive_and_counts_utf8_bytes() {
        let NativePollPayload::Poll(mut poll) = decode_data_url(&data_url(poll_json())).unwrap().payload
            else { panic!("Expected poll") };
        poll.item.title.clear();
        let overhead = serde_json::to_vec(&poll).unwrap().len();
        poll.item.title = "x".repeat(MAX_PAYLOAD_BYTES - overhead);
        let exact = NativePollPayload::Poll(poll.clone());
        assert_eq!(bounded_json(&exact).unwrap().len(), MAX_PAYLOAD_BYTES);
        assert_eq!(decode_data_url(&encode_data_url(&exact).unwrap()).unwrap().payload, exact);
        poll.item.title.push('é');
        assert_eq!(encode_data_url(&NativePollPayload::Poll(poll)), Err(CodecError::PayloadTooLarge));
    }
}
