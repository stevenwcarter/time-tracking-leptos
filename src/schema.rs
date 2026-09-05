//! Diesel table definitions.
//!
//! Hand-written rather than produced by `diesel print-schema`, so the build
//! needs neither the diesel CLI nor a database file present. Keep in sync
//! with `migrations/` by hand.

diesel::table! {
    user (id) {
        id -> Integer,
        email -> Text,
        session_epoch -> BigInt,
        created_at -> Timestamp,
        encrypted_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    time_entry (user_id, entry_date) {
        user_id -> Integer,
        entry_date -> Text,
        body -> Text,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    magic_link_token (id) {
        id -> Integer,
        token_hash -> Binary,
        email -> Text,
        expires_at -> Timestamp,
        used_at -> Nullable<Timestamp>,
        created_at -> Timestamp,
    }
}

diesel::table! {
    passkey_credential (id) {
        id -> Integer,
        user_id -> Integer,
        credential_id -> Binary,
        passkey -> Binary,
        name -> Nullable<Text>,
        prf_capable -> Bool,
        created_at -> Timestamp,
        last_used_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    entry_key_wrap (id) {
        id -> Integer,
        user_id -> Integer,
        kind -> Text,
        credential_id -> Nullable<Binary>,
        wrapped_key -> Binary,
        kdf -> Text,
        wrap_alg -> Text,
        created_at -> Timestamp,
    }
}

diesel::joinable!(time_entry -> user (user_id));
diesel::joinable!(passkey_credential -> user (user_id));
diesel::joinable!(entry_key_wrap -> user (user_id));
diesel::allow_tables_to_appear_in_same_query!(
    user,
    time_entry,
    magic_link_token,
    passkey_credential,
    entry_key_wrap,
);
