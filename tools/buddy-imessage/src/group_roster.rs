// Guarded replies use observations from this worker's uninterrupted APS stream.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use buddy_imessage::{Conversation, GroupGuard, Result, WorkerError, valid_handle};
use rustpush::{APSSendGuard, APSIngressSnapshot, ConversationData, Message, MessageInst, MessageType};
use serde::Serialize;
use uuid::Uuid;

const MAX_ROSTER_AGE_MS: u64 = 60_000;
const INITIAL_WINDOW_MS: u64 = 30_000;
const MAX_BINDINGS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Membership {
    generation: String,
    revision: u64,
    participants: Vec<String>,
}

struct Observation {
    membership: Membership,
    conversation: Conversation,
    received_at_ms: u64,
    participant_version: u64,
}

pub struct GroupSendBinding {
    pub conversation: Conversation,
    pub participant_version: u64,
}

pub struct GroupRoster {
    aps_generation: u64,
    generation: Uuid,
    processed: u64,
    revision: u64,
    continuous: bool,
    bindings: HashMap<Uuid, Observation>,
    invalid: HashSet<Uuid>,
}

fn canonical_handle(value: &str) -> Option<String> {
    let normalized = value.to_ascii_lowercase();
    (normalized.is_ascii() && valid_handle(&normalized)).then_some(normalized)
}

fn exact_roster(participants: &[String]) -> Option<Vec<String>> {
    if participants.len() != 3 { return None; }
    let mut roster = participants.iter().map(|value| canonical_handle(value)).collect::<Option<Vec<_>>>()?;
    roster.sort_unstable();
    if roster.windows(2).any(|pair| pair[0] == pair[1]) { return None; }
    Some(roster)
}

fn thread_id(value: Option<&str>) -> Option<Uuid> {
    let text = value?;
    let id = Uuid::parse_str(text).ok()?;
    (!id.is_nil() && id.to_string().eq_ignore_ascii_case(text)).then_some(id)
}

pub fn operation_matches(guard: &GroupGuard, conversation: &ConversationData) -> bool {
    let thread = thread_id(conversation.sender_guid.as_deref());
    let roster = exact_roster(&conversation.participants);
    thread.is_some() && thread == thread_id(Some(&guard.sender_guid))
        && roster.is_some() && roster == exact_roster(&guard.participants) && conversation.after_guid.is_none()
}

impl GroupRoster {
    pub fn new(ingress: APSIngressSnapshot) -> Self {
        Self { aps_generation: ingress.generation, generation: Uuid::new_v4(), processed: ingress.sequence,
            revision: 0, continuous: ingress.active, bindings: HashMap::new(), invalid: HashSet::new() }
    }

    pub fn invalidate_all(&mut self) {
        self.continuous = false;
        self.bindings.clear();
    }

    pub fn processed(&mut self, ingress: APSIngressSnapshot) {
        if ingress.generation != self.aps_generation || self.processed >= ingress.sequence {
            self.invalidate_all();
        } else {
            self.processed += 1;
        }
    }

    fn invalidate(&mut self, thread: Uuid) {
        self.bindings.remove(&thread);
        if self.invalid.len() >= MAX_BINDINGS { self.invalidate_all(); }
        else { self.invalid.insert(thread); }
    }

    pub fn observe(&mut self, message: &MessageInst, actor: &str, own_handles: &[String], connected_at_ms: u64,
        received_at_ms: u64) -> Option<Membership> {
        if !self.continuous { return None; }
        let conversation = message.conversation.as_ref();
        let thread = thread_id(conversation.and_then(|conversation| conversation.sender_guid.as_deref()));
        if matches!(&message.message, Message::ChangeParticipants(_)) {
            if let Some(thread) = thread { self.invalidate(thread); }
            else { self.invalidate_all(); }
            return None;
        }
        let (Some(conversation), Some(thread)) = (conversation, thread) else {
            if let Some(roster) = conversation.and_then(|conversation| exact_roster(&conversation.participants)) {
                let ambiguous: Vec<_> = self.bindings.iter().filter(|(_, binding)| binding.membership.participants == roster)
                    .map(|(thread, _)| *thread).collect();
                for thread in ambiguous { self.invalidate(thread); }
            }
            return None;
        };
        let normal = matches!(&message.message, Message::Message(normal) if normal.service == MessageType::IMessage);
        if !normal || self.invalid.contains(&thread) { return None; }
        let Some(roster) = exact_roster(&conversation.participants) else {
            if self.bindings.contains_key(&thread) { self.invalidate(thread); }
            return None;
        };
        let Some(participant_version) = message.participant_version else {
            if self.bindings.contains_key(&thread) { self.invalidate(thread); }
            return None;
        };
        let actor_handle = canonical_handle(actor)?;
        let own: Vec<_> = own_handles.iter().filter_map(|handle| canonical_handle(handle)).collect();
        let sender = message.sender.as_deref().and_then(canonical_handle);
        if message.verification_failed || !message.authenticated_madrid_payload
            || !sender.as_ref().is_some_and(|sender| roster.contains(sender))
            || !roster.contains(&actor_handle) || roster.iter().filter(|handle| own.contains(handle)).count() != 1
            || !conversation.participants.iter().any(|handle| handle == actor) {
            if self.bindings.contains_key(&thread) { self.invalidate(thread); }
            return None;
        }
        let fresh = received_at_ms.saturating_sub(connected_at_ms) >= INITIAL_WINDOW_MS
            && message.sent_timestamp >= connected_at_ms
            && received_at_ms.checked_sub(message.sent_timestamp).is_some_and(|age| age <= MAX_ROSTER_AGE_MS);
        if let Some(current) = self.bindings.get_mut(&thread) {
            if current.membership.participants != roster || current.participant_version != participant_version {
                self.invalidate(thread);
                return None;
            }
            if fresh && sender.as_ref().is_some_and(|sender| !own.contains(sender)) {
                current.received_at_ms = received_at_ms;
                current.conversation.cv_name = conversation.cv_name.clone();
            }
            return Some(current.membership.clone());
        }
        if !fresh || sender.as_ref().is_some_and(|sender| own.contains(sender)) { return None; }
        if self.bindings.len() >= MAX_BINDINGS { self.invalidate_all(); return None; }
        self.revision += 1;
        let membership = Membership { generation: self.generation.to_string(), revision: self.revision, participants: roster };
        let conversation = Conversation { participants: conversation.participants.clone(),
            sender_guid: conversation.sender_guid.clone(), cv_name: conversation.cv_name.clone(), after_guid: None };
        self.bindings.insert(thread, Observation { membership: membership.clone(), conversation, received_at_ms,
            participant_version });
        Some(membership)
    }

    pub fn bind(&self, conversation: &Conversation, guard: &GroupGuard, now_ms: u64) -> Result<GroupSendBinding> {
        let thread = thread_id(conversation.sender_guid.as_deref()).ok_or(WorkerError("invalid_group_guard"))?;
        if thread_id(Some(&guard.sender_guid)) != Some(thread) || guard.revision == 0
            || exact_roster(&guard.participants).is_none() || exact_roster(&guard.participants) != exact_roster(&conversation.participants)
            || conversation.after_guid.is_some() || conversation.cv_name.is_some() {
            return Err(WorkerError("invalid_group_guard"));
        }
        self.current(guard, now_ms).map(|binding| GroupSendBinding { conversation: binding.conversation.clone(),
            participant_version: binding.participant_version }).ok_or(WorkerError("group_membership_changed"))
    }

    fn current(&self, guard: &GroupGuard, now_ms: u64) -> Option<&Observation> {
        if !self.continuous { return None; }
        let thread = thread_id(Some(&guard.sender_guid))?;
        let generation = thread_id(Some(&guard.generation))?;
        let roster = exact_roster(&guard.participants)?;
        let binding = self.bindings.get(&thread)?;
        (self.generation == generation && binding.membership.revision == guard.revision
            && binding.membership.participants == roster
            && now_ms.checked_sub(binding.received_at_ms).is_some_and(|age| age <= MAX_ROSTER_AGE_MS)).then_some(binding)
    }
}

pub fn transport_guard(roster: Arc<Mutex<GroupRoster>>, guard: GroupGuard,
    participant_version: u64, now_ms: fn() -> u64) -> APSSendGuard {
    Arc::new(move |ingress| roster.lock().is_ok_and(|roster| {
        ingress.active && roster.aps_generation == ingress.generation && roster.processed == ingress.sequence
            && roster.current(&guard, now_ms()).is_some_and(|binding| binding.participant_version == participant_version)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustpush::{ChangeParticipantMessage, NormalMessage};

    const ACTOR: &str = "mailto:worker@example.test";
    const PEER_A: &str = "mailto:participant-a@example.test";
    const PEER_B: &str = "mailto:participant-b@example.test";
    const THREAD: &str = "00b5f85a-d891-4714-8557-b997ef8f6bc0";
    const SIBLING: &str = "4e038aa2-d497-4293-b994-7316fa715f12";
    const START: u64 = 100_000;
    const NOW: u64 = START + 60_000;

    fn ingress(generation: u64, sequence: u64) -> APSIngressSnapshot {
        APSIngressSnapshot { generation, sequence, active: true }
    }

    fn message(thread: &str, sender: &str, participants: &[&str]) -> MessageInst {
        let conversation = ConversationData { participants: participants.iter().map(|handle| (*handle).into()).collect(),
            sender_guid: Some(thread.into()), cv_name: Some("Synthetic".into()), after_guid: None };
        let mut message = MessageInst::new(conversation, sender,
            Message::Message(NormalMessage::new("Synthetic".into(), MessageType::IMessage)));
        message.sent_timestamp = NOW - 1;
        message.authenticated_madrid_payload = true;
        message.participant_version = Some(3);
        message
    }

    fn observe(roster: &mut GroupRoster, message: &MessageInst) -> Option<Membership> {
        roster.observe(message, ACTOR, &[ACTOR.into()], START, NOW)
    }

    fn group_guard(thread: &str, membership: &Membership) -> GroupGuard {
        GroupGuard { sender_guid: thread.into(), participants: membership.participants.clone(),
            generation: membership.generation.clone(), revision: membership.revision }
    }

    #[test]
    fn binds_both_authenticated_speakers_and_retains_exact_wire_handle() {
        let mut roster = GroupRoster::new(ingress(1, 0));
        let first = message(THREAD, PEER_A, &[ACTOR, "mailto:Participant-A@example.test", PEER_B]);
        let membership = observe(&mut roster, &first).unwrap();
        assert_eq!(membership.revision, 1);
        let second = message(THREAD, PEER_B, &[PEER_B, PEER_A, ACTOR]);
        assert_eq!(observe(&mut roster, &second), Some(membership.clone()));
        let guard = group_guard(THREAD, &membership);
        let request = Conversation { participants: membership.participants, sender_guid: Some(THREAD.into()),
            cv_name: None, after_guid: None };
        let bound = roster.bind(&request, &guard, NOW).unwrap();
        assert!(bound.conversation.participants.contains(&"mailto:Participant-A@example.test".into()));
        assert_eq!(bound.conversation.cv_name.as_deref(), Some("Synthetic"));
        assert_eq!(bound.participant_version, 3);
        assert!(roster.bind(&request, &guard, NOW + MAX_ROSTER_AGE_MS + 1).is_err());
    }

    #[test]
    fn denies_stale_plaintext_and_own_only_bootstrap() {
        let mut roster = GroupRoster::new(ingress(1, 0));
        assert!(observe(&mut roster, &message(THREAD, ACTOR, &[ACTOR, PEER_A, PEER_B])).is_none());
        let mut external = message(THREAD, PEER_A, &[ACTOR, PEER_A, PEER_B]);
        external.authenticated_madrid_payload = false;
        assert!(observe(&mut roster, &external).is_none());
        external.authenticated_madrid_payload = true;
        external.participant_version = None;
        assert!(observe(&mut roster, &external).is_none());
        external.participant_version = Some(3);
        external.sent_timestamp = START - 1;
        assert!(observe(&mut roster, &external).is_none());
    }

    #[test]
    fn rejects_a_change_a_pending_packet_and_a_reconnected_socket() {
        let mut roster = GroupRoster::new(ingress(1, 0));
        let first = message(THREAD, PEER_A, &[ACTOR, PEER_A, PEER_B]);
        let membership = observe(&mut roster, &first).unwrap();
        let sibling = message(SIBLING, PEER_A, &[ACTOR, PEER_A, PEER_B]);
        let sibling_membership = observe(&mut roster, &sibling).unwrap();
        let roster = Arc::new(Mutex::new(roster));
        let guard = transport_guard(roster.clone(), group_guard(THREAD, &membership), 3, || NOW);
        let sibling_guard = transport_guard(roster.clone(), group_guard(SIBLING, &sibling_membership), 3, || NOW);
        let wrong_version = transport_guard(roster.clone(), group_guard(THREAD, &membership), 2, || NOW);
        assert!(guard(ingress(1, 0)));
        assert!(!wrong_version(ingress(1, 0)));
        assert!(!guard(ingress(1, 1)));
        assert!(!guard(ingress(2, 0)));
        {
            let mut roster = roster.lock().unwrap();
            let mut change = first.clone();
            change.message = Message::ChangeParticipants(ChangeParticipantMessage {
                new_participants: vec![ACTOR.into(), PEER_B.into()], group_version: 2,
            });
            roster.processed(ingress(1, 1));
            assert!(observe(&mut roster, &change).is_none());
            assert!(observe(&mut roster, &first).is_none());
        }
        assert!(!guard(ingress(1, 1)));
        assert!(sibling_guard(ingress(1, 1)));
    }

    #[test]
    fn a_conflicting_native_version_retires_the_binding_even_with_the_same_roster() {
        let mut roster = GroupRoster::new(ingress(1, 0));
        let mut first = message(THREAD, PEER_A, &[ACTOR, PEER_A, PEER_B]);
        first.participant_version = Some(0);
        let membership = observe(&mut roster, &first).unwrap();
        let mut changed = first.clone();
        changed.participant_version = Some(1);
        assert!(observe(&mut roster, &changed).is_none());
        assert!(observe(&mut roster, &first).is_none());
        let roster = Arc::new(Mutex::new(roster));
        assert!(!transport_guard(roster, group_guard(THREAD, &membership), 0, || NOW)(ingress(1, 0)));
    }
}
