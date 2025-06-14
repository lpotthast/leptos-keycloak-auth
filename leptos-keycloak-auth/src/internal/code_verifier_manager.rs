use crate::code_verifier;
use crate::code_verifier::{CodeChallenge, CodeVerifier};
use crate::storage::{UseStorageReturn, use_storage_with_options_and_error_handler};
use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_use::storage::StorageType;

#[derive(Debug, Clone, Copy)]
pub struct CodeVerifierManager {
    pub code_verifier: Signal<Option<CodeVerifier<128>>>,
    pub(crate) set_code_verifier: WriteSignal<Option<CodeVerifier<128>>>,
    pub code_challenge: Memo<Option<CodeChallenge>>,
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
        } = use_storage_with_options_and_error_handler::<Option<CodeVerifier<128>>, JsonSerdeCodec>(
            // Forcing session storage, because this data point must be as secure as possible,
            // and we do not care that we may lose the code from a page-refresh or tab-close.
            StorageType::Session,
            "leptos_keycloak_auth__code_verifier",
            None,
        );

        if code_verifier.read_untracked().is_none() {
            tracing::trace!("No code_verifier found in session storage, generating new one...");
            set_code_verifier.set(Some(CodeVerifier::<128>::generate()));
        }
        let code_challenge = Memo::new(move |_| {
            code_verifier
                .read()
                .as_ref()
                .map(|it| it.to_code_challenge())
        });

        Self {
            code_verifier,
            set_code_verifier,
            code_challenge,
        }
    }

    pub(crate) fn regenerate(&self) {
        #[allow(unused_qualifications)]
        self.set_code_verifier
            .set(Some(code_verifier::CodeVerifier::<128>::generate()));
    }
}
