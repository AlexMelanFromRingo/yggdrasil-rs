//! In-band session packet type tags.
//!
//! Port of yggdrasil-go/src/core/types.go

// Session-level packet types (first byte of payload from ironwood)
pub const TYPE_SESSION_DUMMY: u8 = 0;
pub const TYPE_SESSION_TRAFFIC: u8 = 1;
pub const TYPE_SESSION_PROTO: u8 = 2;

// Protocol sub-packet types (byte after TYPE_SESSION_PROTO)
pub const TYPE_PROTO_DUMMY: u8 = 0;
pub const TYPE_PROTO_NODE_INFO_REQUEST: u8 = 1;
pub const TYPE_PROTO_NODE_INFO_RESPONSE: u8 = 2;
pub const TYPE_PROTO_DEBUG: u8 = 255;

// Debug sub-types (byte after TYPE_PROTO_DEBUG)
pub const TYPE_DEBUG_DUMMY: u8 = 0;
pub const TYPE_DEBUG_GET_SELF_REQUEST: u8 = 1;
pub const TYPE_DEBUG_GET_SELF_RESPONSE: u8 = 2;
pub const TYPE_DEBUG_GET_PEERS_REQUEST: u8 = 3;
pub const TYPE_DEBUG_GET_PEERS_RESPONSE: u8 = 4;
pub const TYPE_DEBUG_GET_TREE_REQUEST: u8 = 5;
pub const TYPE_DEBUG_GET_TREE_RESPONSE: u8 = 6;
