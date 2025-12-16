use crate::code_verifier::CodeVerifier;
use crate::config::Options;
use crate::internal::{JwkSetWithTimestamp, OidcConfigWithTimestamp};
use crate::{
    request::{self, RequestError}, token::TokenData, AuthorizationCode, DiscoveryEndpoint, JwkSetEndpoint,
    RefreshToken,
    SessionState,
    TokenEndpoint,
};
use leptos::prelude::*;
use time::OffsetDateTime;

pub(crate) fn create_retrieve_oidc_config_action(
    set_oidc_config_wt: Callback<Option<OidcConfigWithTimestamp>>,
    set_req_error: Callback<Option<RequestError>>,
) -> Action<(DiscoveryEndpoint,), ()> {
    Action::new(move |(discovery_endpoint,): &(DiscoveryEndpoint,)| {
        let discovery_endpoint = discovery_endpoint.clone();
        async move {
            leptos::task::spawn_local(async move {
                let result = request::retrieve_oidc_config(discovery_endpoint.clone()).await;
                match result {
                    Ok(oidc_config) => {
                        set_oidc_config_wt.run(Some(OidcConfigWithTimestamp {
                            oidc_config,
                            retrieved: OffsetDateTime::now_utc(),
                            source: discovery_endpoint,
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
) -> Action<(JwkSetEndpoint, DiscoveryEndpoint), ()> {
    Action::new(
        move |(jwk_set_endpoint, discovery_endpoint): &(JwkSetEndpoint, DiscoveryEndpoint)| {
            let jwk_set_endpoint = jwk_set_endpoint.clone();
            let discovery_endpoint = discovery_endpoint.clone();
            async move {
                leptos::task::spawn_local(async move {
                    let result = request::retrieve_jwk_set(jwk_set_endpoint).await;
                    match result {
                        Ok(jwk_set) => {
                            set_jwk_set_wt.run(Some(JwkSetWithTimestamp {
                                jwk_set,
                                retrieved: OffsetDateTime::now_utc(),
                                source: discovery_endpoint,
                            }));
                        }
                        Err(err) => {
                            tracing::error!(?err, "Could not retrieve JWK set.");
                            set_req_error.run(Some(err));
                        }
                    }
                });
            }
        },
    )
}

pub struct ExchangeCodeForTokenInput {
    pub(crate) token_endpoint: TokenEndpoint,
    pub(crate) auth_code: AuthorizationCode,
    pub(crate) code_verifier: CodeVerifier<128>,
    pub(crate) session_state: Option<SessionState>,
    pub(crate) finally: Callback<()>,
}

pub(crate) fn create_exchange_code_for_token_action(
    options: StoredValue<Options>,
    set_token: Callback<Option<TokenData>>,
    set_req_error: Callback<Option<RequestError>>,
) -> Action<ExchangeCodeForTokenInput, ()> {
    Action::new(move |input: &ExchangeCodeForTokenInput| {
        let token_endpoint = input.token_endpoint.clone();
        let client_id = options.read_value().client_id.clone();
        let redirect_uri = options.read_value().post_login_redirect_url;
        let auth_code = input.auth_code.clone();
        let code_verifier = input.code_verifier.code_verifier().to_owned();
        let session_state = input.session_state.clone();
        let finally = input.finally;
        async move {
            leptos::task::spawn_local(async move {
                let result = request::exchange_code_for_token(
                    token_endpoint,
                    &client_id,
                    redirect_uri.read_untracked().as_ref(),
                    &auth_code,
                    &code_verifier,
                    session_state.as_deref(),
                    options.read_value().discovery_endpoint(),
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
                finally.run(());
            });
        }
    })
}

#[allow(clippy::type_complexity)]
pub(crate) fn create_refresh_token_action(
    options: StoredValue<Options>,
    set_token: Callback<Option<TokenData>>,
    set_req_error: Callback<Option<RequestError>>,
) -> Action<
    (
        TokenEndpoint,
        RefreshToken,
        Callback<(RequestError,), RequestError>,
    ),
    (),
> {
    Action::new(
        move |(token_endpoint, refresh_token, on_refresh_error): &(
            TokenEndpoint,
            RefreshToken,
            Callback<(RequestError,), RequestError>,
        )| {
            let token_endpoint = token_endpoint.clone();
            let client_id = options.read_value().client_id.clone();
            let refresh_token = refresh_token.clone();
            let on_refresh_error = *on_refresh_error;
            async move {
                leptos::task::spawn_local(async move {
                    match request::refresh_token(
                        token_endpoint,
                        &client_id,
                        &refresh_token,
                        options.read_value().discovery_endpoint(),
                    )
                    .await
                    {
                        Ok(refreshed_token) => set_token.run(Some(refreshed_token)),
                        Err(err) => {
                            let err = on_refresh_error.run((err,));
                            set_req_error.run(Some(err));
                        }
                    }
                });
            }
        },
    )
}
