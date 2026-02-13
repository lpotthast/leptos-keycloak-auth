use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_use::storage::StorageType;

use crate::{
    nonce::Nonce,
    storage::{UseStorageReturn, use_storage_with_options_and_error_handler},
};

/// Manages [`Nonce`](Nonce)'s  for `OpenID Connect` ID token validation.
///
/// Nonces are stored in session storage because the authorization flow involves
/// navigating away from the application to Keycloak's login page and then being redirected
/// back, which causes a full page reload. Session storage survives same-tab navigations.
///
/// # Internal Use
/// This is an internal component exposed via the `internals` feature flag for advanced
/// use cases like testing or debugging.
#[derive(Clone, Copy, Debug)]
pub struct NonceManager {
    /// The currently active nonce.
    nonce: Signal<Nonce>,

    /// Setter for the nonce.
    set_nonce: Callback<Nonce>,
}

impl NonceManager {
    /// Create a new nonce manager.
    ///
    /// The nonce is stored in session storage to survive full page reloads during the
    /// OAuth/OIDC authorization flow.
    pub fn new() -> Self {
        // We keep the nonce in session storage because our authorization flow includes
        // navigating away from our Leptos application to the auth provider's login page
        // and then being redirected back to our application, meaning that we do a full reload!
        // We include the nonce in the authorization request and need the same nonce later
        // to validate the ID token, giving us no other way than storing it.
        let UseStorageReturn {
            read: nonce,
            write: set_nonce,
            remove: _remove_nonce_from_storage,
            ..
        } = use_storage_with_options_and_error_handler::<Nonce, JsonSerdeCodec>(
            // Forcing session storage, because this data point must be as secure as possible,
            // and we do not care that we may lose the nonce from a page-refresh or tab-close.
            StorageType::Session,
            "leptos_keycloak_auth__nonce",
            move || {
                tracing::trace!("Create initial nonce");
                Nonce::new()
            },
        );

        Self { nonce, set_nonce }
    }

    /// Get the current nonce signal.
    pub fn nonce(&self) -> Signal<Nonce> {
        self.nonce
    }

    /// Generate a new nonce for the next authorization flow.
    pub fn regenerate(&self) {
        self.set_nonce.run(Nonce::new());
    }
}

impl Default for NonceManager {
    fn default() -> Self {
        Self::new()
    }
}
