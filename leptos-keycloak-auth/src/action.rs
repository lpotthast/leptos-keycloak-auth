use leptos::prelude::*;
use time::OffsetDateTime;
use url::Url;

use crate::code_verifier::CodeVerifier;
use crate::{
    config::UseKeycloakAuthOptions,
    request::{self, RequestError},
    token::TokenData,
    AuthorizationCode, DiscoveryEndpoint, JwkSetEndpoint, JwkSetWithTimestamp,
    OidcConfigWithTimestamp, RefreshToken, SessionState, TokenEndpoint,
};

pub(crate) fn create_retrieve_oidc_config_action(
    discovery_endpoint_url: DiscoveryEndpoint,
    set_oidc_config_wt: Callback<Option<OidcConfigWithTimestamp>>,
    set_req_error: Callback<Option<RequestError>>,
) -> Action<(), ()> {
    Action::new(move |(): &()| {
        let discovery_endpoint_url = discovery_endpoint_url.clone();
        async move {
            leptos::task::spawn_local(async move {
                let result = request::retrieve_oidc_config(discovery_endpoint_url).await;
                match result {
                    Ok(oidc_config) => {
                        set_oidc_config_wt.run(Some(OidcConfigWithTimestamp {
                            oidc_config,
                            retrieved: OffsetDateTime::now_utc(),
                        }));
                    }
                    Err(err) => {
                        tracing::error!(?err, "Could not retrieve OIDC config through discovery.");
                        set_req_error.run(Some(err));
                    }
                }
            });
        }
    })
}

pub(crate) fn create_retrieve_jwk_set_action(
    set_jwk_set_wt: Callback<Option<JwkSetWithTimestamp>>,
    set_req_error: Callback<Option<RequestError>>,
) -> Action<Url, ()> {
    Action::new(move |jwk_set_endpoint: &JwkSetEndpoint| {
        let jwk_set_endpoint = jwk_set_endpoint.clone();
        async move {
            leptos::task::spawn_local(async move {
                let result = request::retrieve_jwk_set(jwk_set_endpoint).await;
                match result {
                    Ok(jwk_set) => {
                        set_jwk_set_wt.run(Some(JwkSetWithTimestamp {
                            jwk_set,
                            retrieved: OffsetDateTime::now_utc(),
                        }));
                    }
                    Err(err) => {
                        tracing::error!(?err, "Could not retrieve JWK set.");
                        set_req_error.run(Some(err));
                    }
                }
            });
        }
    })
}

pub(crate) fn create_exchange_code_for_token_action(
    options: StoredValue<UseKeycloakAuthOptions>,
    set_token: Callback<Option<TokenData>>,
    set_req_error: Callback<Option<RequestError>>,
) -> Action<
    (
        TokenEndpoint,
        AuthorizationCode,
        CodeVerifier<128>,
        Option<SessionState>,
    ),
    (),
> {
    Action::new(
        move |(token_endpoint, code, verifier, session_state): &(
            TokenEndpoint,
            AuthorizationCode,
            CodeVerifier<128>,
            Option<SessionState>,
        )| {
            let token_endpoint = token_endpoint.clone();
            let client_id = options.read_value().client_id.clone();
            let redirect_uri = options.read_value().post_login_redirect_url.clone();
            let code = code.clone();
            let code_verifier = verifier.code_verifier().to_owned();
            let session_state = session_state.clone();
            async move {
                leptos::task::spawn_local(async move {
                    let result = request::exchange_code_for_token(
                        token_endpoint,
                        &client_id,
                        redirect_uri.as_str(),
                        &code,
                        &code_verifier,
                        session_state.as_ref().map(|s| s.as_str()),
                    )
                    .await;
                    match result {
                        Ok(token) => {
                            set_token.run(Some(token));
                        }
                        Err(err) => {
                            set_req_error.run(Some(err));
                        }
                    }
                });
            }
        },
    )
}

pub(crate) fn create_refresh_token_action(
    options: StoredValue<UseKeycloakAuthOptions>,
    set_token: Callback<Option<TokenData>>,
    set_req_error: Callback<Option<RequestError>>,
) -> Action<(TokenEndpoint, RefreshToken), ()> {
    Action::new(
        move |(token_endpoint, refresh_token): &(TokenEndpoint, RefreshToken)| {
            let token_endpoint = token_endpoint.clone();
            let client_id = options.read_value().client_id.clone();
            let refresh_token = refresh_token.clone();
            async move {
                leptos::task::spawn_local(async move {
                    match request::refresh_token(token_endpoint, &client_id, &refresh_token).await {
                        Ok(refreshed_token) => set_token.run(Some(refreshed_token)),
                        Err(err) => set_req_error.run(Some(err)),
                    }
                });
            }
        },
    )
}
