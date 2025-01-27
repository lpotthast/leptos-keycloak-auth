use crate::internal::derived_urls::DerivedUrlError;
use crate::token::TokenData;
use crate::{EndSessionEndpoint, UseKeycloakAuthOptions};
use leptos::prelude::*;
use url::Url;

pub(crate) fn create_logout_url_signal(
    end_session_endpoint: Signal<Result<EndSessionEndpoint, DerivedUrlError>>,
    token: Signal<Option<TokenData>>,
    options: StoredValue<UseKeycloakAuthOptions>,
) -> Memo<Option<Url>> {
    Memo::new(move |_| {
        let end_session_endpoint = match end_session_endpoint.read().as_ref() {
            Ok(it) => it.clone(),
            Err(_) => return Option::<Url>::None,
        };

        let mut post_logout_redirect_url = options.read_value().post_logout_redirect_url.clone();
        post_logout_redirect_url
            .query_pairs_mut()
            .append_pair("destroy_session", "true");

        let mut logout_url: Url = end_session_endpoint;
        logout_url.query_pairs_mut().append_pair(
            "post_logout_redirect_uri",
            post_logout_redirect_url.as_str(),
        );
        if let Some(token_data) = token.read().as_ref() {
            logout_url
                .query_pairs_mut()
                .append_pair("id_token_hint", &token_data.id_token);
        }
        Some(logout_url)
    })
}
