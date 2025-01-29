use crate::code_verifier::CodeChallenge;
use crate::config::Options;
use crate::internal::derived_urls::DerivedUrlError;
use crate::AuthorizationEndpoint;
use leptos::prelude::*;
use url::Url;

pub(crate) fn create_login_url_signal(
    authorization_endpoint: Signal<Result<AuthorizationEndpoint, DerivedUrlError>>,
    options: StoredValue<Options>,
    code_challenge: Memo<Option<CodeChallenge>>,
) -> Memo<Option<Url>> {
    Memo::new(move |_| {
        let authorization_endpoint = match authorization_endpoint.read().as_ref() {
            Ok(it) => it.clone(),
            Err(_) => return Option::<Url>::None,
        };
        let code_challenge = match code_challenge.get() {
            Some(it) => it,
            None => return Option::<Url>::None,
        };

        let mut login_url: Url = authorization_endpoint;
        login_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("code_challenge", code_challenge.code_challenge())
            .append_pair(
                "code_challenge_method",
                code_challenge.code_challenge_method().as_str(),
            )
            .append_pair(
                "client_id",
                &options.with_value(|params| params.client_id.clone()),
            )
            .append_pair(
                "redirect_uri",
                options
                    .with_value(|params| params.post_login_redirect_url.read())
                    .as_str(),
            )
            .append_pair(
                "scope",
                &options.with_value(|params| params.scope.clone().unwrap_or("openid".to_owned())),
            );
        Some(login_url)
    })
}
