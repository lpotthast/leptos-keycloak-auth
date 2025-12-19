use crate::code_verifier::{CodeChallenge, CodeVerifier};
use crate::storage::{use_storage_with_options_and_error_handler, UseStorageReturn};
use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_use::storage::StorageType;

/// Manages PKCE code verifiers and challenges for secure authorization flows.
///
/// The `CodeVerifierManager` is responsible for:
/// - Generating cryptographically secure code verifiers
/// - Deriving code challenges from verifiers
/// - Storing verifiers in session storage to survive navigation
/// - Regenerating verifiers for new authorization flows
///
/// Code verifiers are stored in session storage because the authorization flow involves
/// navigating away from the application to Keycloak's login page and then being redirected
/// back, which causes a full page reload.
///
/// # Internal Use
/// This is an internal component exposed via the `internals` feature flag for advanced
/// use cases like testing or debugging.
#[derive(Debug, Clone, Copy)]
pub struct CodeVerifierManager {
    pub code_verifier: Signal<CodeVerifier<128>>,
    pub(crate) set_code_verifier: Callback<CodeVerifier<128>>,

    pub code_challenge: Memo<CodeChallenge>,
}

impl CodeVerifierManager {
    pub(crate) fn new() -> Self {
        // We keep the code_verifier, used for the code-to-token-exchange in session storage.
        // We cannot keep the code_verifier completely in-memory, as our authorization flow includes
        // navigating away from our Leptos application to the auth-providers login page and then
        // being redirected back to our application, meaning that we do a full reload!
        // But: We have to provide the code_verifier derived code_challenge on navigation away from
        // our app and need the same code_verifier later to do the token exchange, giving us no other
        // way than storing it.
        // TODO: Can we provide an "iframe" mode in which the login page is shown in an iframe while our Leptos application stays running in the background?
        let UseStorageReturn {
            read: code_verifier,
            write: set_code_verifier,
            remove: _remove_code_verifier_from_storage,
            ..
        } = use_storage_with_options_and_error_handler::<CodeVerifier<128>, JsonSerdeCodec>(
            // Forcing session storage, because this data point must be as secure as possible,
            // and we do not care that we may lose the code from a page-refresh or tab-close.
            StorageType::Session,
            "leptos_keycloak_auth__code_verifier",
            move || CodeVerifier::<128>::generate(),
        );

        let code_challenge = Memo::new(move |_| code_verifier.read().to_code_challenge());

        Self {
            code_verifier,
            set_code_verifier,
            code_challenge,
        }
    }

    pub(crate) fn regenerate(&self) {
        self.set_code_verifier.run(CodeVerifier::<128>::generate());
    }
}
