use std::fmt::Display;

/// The maximum length in bytes of a tag. Since tags are ascii, this
/// is also the maximum length in characters.
///
/// This was informed by the pre-existing CRDB limit in omicron:
///
/// <https://github.com/oxidecomputer/omicron/blob/main/schema/crdb/dbinit.sql#L8875>
const TAG_CAPACITY: usize = 63;

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
// `heapless::String` is annoying for a variety of reasons. First, it
// doesn't implement `Copy`, which is conceptually warranted in a
// stack allocated type.
//
// Worse, it doesn't optimize size. For example, a 63 byte array on
// a 64-bit machine should take up 64 bytes in total. Wasting a full
// usize when we need no more than a u6 is extravagant dissipation imho.
//
// But a bespoke stack string isn't warranted scope for this initial PR,
// so that's a (possibly unnecessary) optimization for another day. And
// it can live entirely behind this API anyway.
#[repr(transparent)]
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Tag(heapless::String<TAG_CAPACITY>);

// TODO::cory: kit this out with all sorts of accoutrements
// - Constructor with type checking: rip from multicast.
//   - Const constructor?
//   - FromStr?
// - as_str, AsRef<str>, to from conversions
// - Serialization

const _: () =
    assert_eq!(std::mem::size_of::<Tag>(), 72, "this could be 64 if we tried");

impl Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.as_str().fmt(f)
    }
}
