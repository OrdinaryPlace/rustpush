// Modified 2026-10-27 for OrdinaryPlace Buddy. SSPL v1; see LICENSE.
//! Shared dictionary serializer used by the production native balloon path.
//! Generic wrapper fields keep this small module testable without Apple auth.

use plist::Dictionary;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawBalloonData<Layout, Binary, Session, Url> {
    pub(crate) ldtext: Option<String>,
    #[serde(flatten)]
    pub(crate) layout: Option<Layout>,
    #[serde(rename = "an")]
    pub(crate) app_name: String,
    #[serde(rename = "ai")]
    pub(crate) app_icon: Option<Binary>,
    pub(crate) session_identifier: Option<Session>,
    pub(crate) live_layout_info: Option<Binary>,
    pub(crate) required_capabilities: Option<Binary>,
    pub(crate) send_as_text: Option<bool>,
    #[serde(rename = "URL")]
    pub(crate) url: Url,
    pub(crate) appid: Option<u64>,
}

impl<Layout, Binary, Session, Url> Serialize for RawBalloonData<Layout, Binary, Session, Url>
where Layout: Serialize, Binary: Serialize, Session: Serialize, Url: Serialize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let mut dict = Dictionary::from_iter([
            ("an".to_string(), self.app_name.clone().into()),
            ("URL".to_string(), plist::to_value(&self.url).map_err(serde::ser::Error::custom)?)
        ]);
        if let Some(layout) = &self.layout {
            let serialized = plist::to_value(layout).map_err(serde::ser::Error::custom)?;
            let dictionary = serialized.into_dictionary()
                .ok_or_else(|| serde::ser::Error::custom("Balloon layout must be a dictionary"))?;
            dict.extend(dictionary);
        }
        if let Some(icon) = &self.app_icon {
            dict.insert("ai".to_string(), plist::to_value(icon).map_err(serde::ser::Error::custom)?);
        }
        if let Some(appid) = self.appid {
            dict.insert("appid".to_string(), appid.into());
        }
        if let Some(text) = &self.ldtext {
            dict.insert("ldtext".to_string(), text.clone().into());
        }
        if let Some(session) = &self.session_identifier {
            dict.insert("sessionIdentifier".to_string(), plist::to_value(session).map_err(serde::ser::Error::custom)?);
        }
        if let Some(live) = &self.live_layout_info {
            dict.insert("liveLayoutInfo".to_string(), plist::to_value(live).map_err(serde::ser::Error::custom)?);
        }
        if let Some(capabilities) = &self.required_capabilities {
            dict.insert("requiredCapabilities".to_string(), plist::to_value(capabilities).map_err(serde::ser::Error::custom)?);
        }
        if let Some(send_as_text) = self.send_as_text {
            dict.insert("sendAsText".to_string(), send_as_text.into());
        }
        dict.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::Value;

    type Raw = RawBalloonData<Dictionary, Value, Value, Value>;

    fn fixture() -> Raw {
        Raw {
            ldtext: Some("Sent a poll".into()),
            layout: Some(Dictionary::from_iter([
                ("layoutClass".to_string(), Value::String("MSMessageTemplateLayout".to_string())),
                ("userInfo".to_string(), Value::Dictionary(Dictionary::new())),
            ])),
            app_name: "Polls".into(),
            app_icon: None,
            session_identifier: Some(Value::Data(vec![1; 16])),
            live_layout_info: Some(Value::Data(vec![2, 3])),
            required_capabilities: Some(Value::Data(vec![4, 5, 6])),
            send_as_text: Some(true),
            url: Value::String("data:,synthetic".into()),
            appid: None,
        }
    }

    #[test]
    fn actual_balloon_dictionary_preserves_native_poll_fields() {
        let value = plist::to_value(&fixture()).unwrap();
        let dict = value.as_dictionary().unwrap();
        assert_eq!(dict["requiredCapabilities"], Value::Data(vec![4, 5, 6]));
        assert_eq!(dict["sendAsText"], Value::Boolean(true));
        assert_eq!(dict["sessionIdentifier"], Value::Data(vec![1; 16]));
        assert_eq!(dict["layoutClass"], Value::String("MSMessageTemplateLayout".into()));
        // Production decodes this inside NSDictionary<Raw>, whose flattened
        // content uses implicit Option values. Direct-root plist deserialization
        // has different Option semantics and is not the production envelope.
        #[derive(Deserialize)]
        struct Envelope {
            #[serde(rename = "$class")]
            class: String,
            #[serde(flatten)]
            item: Raw,
        }
        let mut wrapped = value.clone();
        wrapped.as_dictionary_mut().unwrap().insert("$class".to_string(), Value::String("NSMutableDictionary".to_string()));
        let decoded: Envelope = plist::from_value(&wrapped).unwrap();
        assert_eq!(decoded.class, "NSMutableDictionary");
        assert_eq!(plist::to_value(&decoded.item).unwrap(), value);
    }

    #[test]
    fn missing_poll_fields_are_omitted_and_false_is_preserved() {
        let mut raw = fixture();
        raw.required_capabilities = None;
        raw.send_as_text = None;
        let value = plist::to_value(&raw).unwrap();
        let dict = value.as_dictionary().unwrap();
        assert!(!dict.contains_key("requiredCapabilities"));
        assert!(!dict.contains_key("sendAsText"));
        raw.send_as_text = Some(false);
        assert_eq!(plist::to_value(&raw).unwrap().as_dictionary().unwrap()["sendAsText"], Value::Boolean(false));
    }

    #[test]
    fn non_dictionary_layout_returns_an_error_without_panicking() {
        let raw = RawBalloonData::<Value, Value, Value, Value> {
            ldtext: None, layout: Some(Value::String("invalid".into())),
            app_name: "Polls".into(), app_icon: None, session_identifier: None,
            live_layout_info: None, required_capabilities: None, send_as_text: None,
            url: Value::String("data:,synthetic".into()), appid: None,
        };
        assert!(plist::to_value(&raw).is_err());
    }
}
