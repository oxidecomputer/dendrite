use std::{
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::LazyLock,
};

use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1::{link::LinkId, port::PortId};

/// The maximum length in bytes of a tag. Since tags are ascii, this
/// is also the maximum length in characters.
///
/// This was informed by the pre-existing CRDB limit for dpd
/// multicast groups in omicron:
///
/// <https://github.com/oxidecomputer/omicron/blob/main/schema/crdb/dbinit.sql#L8875>
const TAG_CAPACITY: usize = 63;

/// Defines the acceptable character range of a tag.
///
/// This particular pattern mirrors that already used for multicast
/// resource tags.
static TAG_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_.:-]+$").unwrap());

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(
        "Input text {given:?} failed to match the validation regex {pattern:?}"
    )]
    Pattern { given: String, pattern: String },

    #[error(
        "Tag length must be in the range {range:?}. Found {0}.", range = 1..=TAG_CAPACITY
    )]
    Size(usize),
}

/// An ID used to namespace and network resources. Tags allow
/// different parties to CRUD resources without affecting each other.
///
/// Tags are an internal mechanism for categorization. They don't
/// enforce authentication, and most will probably be hardcoded strings.
///
/// This usage is somewhat analagous to FRR's [RTPROT](https://github.com/FRRouting/frr/blob/master/include/linux/rtnetlink.h#L286-L310) type.
//
// Implementation notes:
//
// `heapless::String` is annoying for a variety of reasons.
//
// 1. It doesn't implement `Copy`, which is conceptually the whole
//    point of a stack allocated type.
// 2. It doesn't optimize size. For example, a 63 byte array on
//    a 64-bit machine should take up 64 bytes in total. Wasting a full
//    usize when we need no more than a u6 is extravagant dissipation imho.
// 3. It doesn't expose any non-trivial const constructor, which feels like
//    a missed opportunity.
//
// But a bespoke stack string isn't warranted scope for this initial PR,
// so that's an optimization for another day. And it can live behind
// this API anyway.
#[repr(transparent)]
#[derive(
    serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, Clone, Hash,
)]
pub struct Tag(heapless::String<TAG_CAPACITY>);
const _: () =
    assert!(std::mem::size_of::<Tag>() == 72, "this could be 64 if we tried");

// TODO::cory: tests are warranted

impl Tag {
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }

    pub fn coerce(tag: &str) -> Self {
        const FILLER: &str = "_";

        let mut good = heapless::String::<TAG_CAPACITY>::new();
        for ch in tag.chars() {
            let mut buf = [0u8; 4];
            let mut ch = &*ch.encode_utf8(&mut buf);

            if !TAG_PATTERN.is_match(ch) {
                ch = FILLER;
            }

            if good.push_str(ch).is_err() {
                break;
            }
        }

        if good.is_empty() {
            good.push_str(FILLER)
                .expect("Empty buf must have space for a char");
        }

        good.as_str().parse().expect("coerced tag should always be valid")
    }
}

impl FromStr for Tag {
    type Err = self::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !TAG_PATTERN.is_match(s) {
            return Err(self::Error::Pattern {
                given: s.to_string(),
                pattern: TAG_PATTERN.to_string(),
            });
        }

        heapless::String::from_str(s)
            .map_or_else(|_| Err(self::Error::Size(s.len())), |s| Ok(Self(s)))
    }
}

impl JsonSchema for Tag {
    fn schema_name() -> String {
        String::from(stringify!(Tag))
    }

    fn json_schema(
        generator: &mut schemars::r#gen::SchemaGenerator,
    ) -> schemars::schema::Schema {
        let mut schema = String::json_schema(generator);
        let schemars::schema::Schema::Object(object) = &mut schema else {
            unreachable!();
        };
        object.metadata().description.replace(String::from(
            "A text label for namespacing network resources and actions",
        ));
        object.string().min_length = Some(1);
        object.string().max_length = Some(TAG_CAPACITY as u32);
        object.string().pattern = Some(TAG_PATTERN.to_string());
        schema
    }
}

impl AsRef<str> for Tag {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().fmt(f)
    }
}

/// An IPv6 address assigned to a link.
#[derive(Deserialize, Serialize, JsonSchema, Debug, Clone)]
pub struct Ipv6Entry {
    /// Client-side tag for this object.
    pub tag: Tag,
    /// The IP address.
    pub addr: Ipv6Addr,
}

/// An IPv4 address assigned to a link.
#[derive(Deserialize, Serialize, JsonSchema, Debug, Clone)]
pub struct Ipv4Entry {
    /// Client-side tag for this object.
    pub tag: Tag,
    /// The IP address.
    pub addr: Ipv4Addr,
}

impl From<crate::v1::port::Ipv4Entry> for Ipv4Entry {
    fn from(prev: crate::v1::port::Ipv4Entry) -> Self {
        Self { addr: prev.addr, tag: Tag::coerce(&prev.tag) }
    }
}

impl From<Ipv4Entry> for crate::v1::port::Ipv4Entry {
    fn from(value: Ipv4Entry) -> Self {
        Self { addr: value.addr, tag: value.tag.to_string() }
    }
}

/// Identifies a logical link on a physical port.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct TaggedLinkPath {
    /// The switch port on which to operate.
    pub port_id: PortId,
    /// The link in the switch port on which to operate.
    pub link_id: LinkId,
    /// Defines the tag scope of this request/response. If None,
    /// this applies to all tags.
    pub tag: Option<Tag>,
}

impl From<crate::v1::link::LinkPath> for TaggedLinkPath {
    fn from(path: crate::v1::link::LinkPath) -> Self {
        Self { port_id: path.port_id, link_id: path.link_id, tag: None }
    }
}
