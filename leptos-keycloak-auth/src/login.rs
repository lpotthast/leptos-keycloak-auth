use crate::code_verifier::CodeChallenge;
use crate::config::Options;
use crate::internal::derived_urls::DerivedUrlError;
use crate::nonce::Nonce;
use crate::AuthorizationEndpoint;
use itertools::Itertools;
use leptos::prelude::*;
use std::borrow::Cow;
use url::Url;

pub(crate) fn create_login_url_signal(
    authorization_endpoint: Signal<Result<AuthorizationEndpoint, DerivedUrlError>>,
    options: StoredValue<Options>,
    code_challenge: Memo<CodeChallenge>,
    nonce: Signal<Nonce>,
) -> Memo<Option<Url>> {
    Memo::new(move |_| {
        let authorization_endpoint = match authorization_endpoint.read().as_ref() {
            Ok(it) => it.clone(),
            Err(_) => return Option::<Url>::None,
        };
        let code_challenge = code_challenge.read();
        let nonce = nonce.read();
        let options = options.read_value();
        let scope = match options.scope.len() {
            0 => Cow::Borrowed("openid"),
            _ => Cow::Owned(
                options
                    .scope
                    .iter()
                    .map(|it| it.trim())
                    .chain(["openid"])
                    .join(" "),
            ),
        };

        let login_url = create_login_url(
            authorization_endpoint,
            &code_challenge,
            &nonce,
            &options.client_id,
            options.post_login_redirect_url.read().as_str(),
            &scope,
        );
        Some(login_url)
    })
}

fn create_login_url(
    authorization_endpoint: Url,
    code_challenge: &CodeChallenge,
    nonce: &Nonce,
    client_id: &str,
    post_login_redirect_url: &str,
    scope: &str,
) -> Url {
    let mut login_url: Url = authorization_endpoint;
    login_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("code_challenge", code_challenge.code_challenge())
        .append_pair(
            "code_challenge_method",
            code_challenge.code_challenge_method().as_str(),
        )
        .append_pair("nonce", nonce.as_str())
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", post_login_redirect_url)
        .append_pair("scope", scope);
    login_url
}
