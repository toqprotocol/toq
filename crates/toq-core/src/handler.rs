//! Handler filter matching for message dispatch.

use crate::config::HandlerEntry;
use crate::crypto::PublicKey;
use crate::policy::address_matches;

/// Check whether a message matches a handler's filters.
///
/// Rules:
/// - No filters = matches all messages.
/// - Same filter type = OR (any match within the type).
/// - Different filter types = AND (all types must match).
pub fn matches_handler(
    handler: &HandlerEntry,
    from_address: &str,
    from_key: Option<&PublicKey>,
    msg_type: &str,
) -> bool {
    if !handler.enabled {
        return false;
    }

    let from_ok = handler.filter_from.is_empty()
        || handler
            .filter_from
            .iter()
            .any(|pat| address_matches(pat, from_address));

    let key_ok = handler.filter_key.is_empty()
        || from_key.is_some_and(|pk| {
            let encoded = pk.to_encoded();
            handler.filter_key.iter().any(|k| k == &encoded)
        });

    let type_ok =
        handler.filter_type.is_empty() || handler.filter_type.iter().any(|t| t == msg_type);

    from_ok && key_ok && type_ok
}
