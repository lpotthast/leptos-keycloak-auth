use crate::config::Options;
use crate::csrf_token::CsrfToken;
use crate::internal::derived_urls::DerivedUrlError;
use crate::token::TokenData;
use crate::EndSessionEndpoint;
use leptos::prelude::*;
use url::Url;

pub(crate) fn create_logout_url_signal(
    end_session_endpoint: Signal<Result<EndSessionEndpoint, DerivedUrlError>>,
    token: Signal<Option<TokenData>>,
    options: StoredValue<Options>,
    pending_hydration: Signal<bool>,
    csrf_token: Signal<CsrfToken>,
) -> Memo<Option<Url>> {
    Memo::new(move |_| {
        // Only creating the url (and accessing relevant signals) when not hydrating anymore,
        // forces recreation and re-rendering of the url.
        // If this is not done, the signal returned from this function may contain a value that is
        // not actually reflected to the UI, as it only changed during hydration...
        if pending_hydration.get() {
            return None;
        }

        let end_session_endpoint = match end_session_endpoint.read().as_ref() {
            Ok(it) => it.clone(),
            Err(_) => return Option::<Url>::None,
        };

        Some(create_logout_url(
            end_session_endpoint,
            options.read_value().post_logout_redirect_url.get(),
            token.read().as_ref().map(|it| it.id_token.as_str()),
            &csrf_token.read(),
        ))
    })
}

pub(crate) fn create_logout_url(
    mut end_session_endpoint: EndSessionEndpoint,
    mut post_logout_redirect_uri: Url,
    id_token_hint: Option<&str>,
    logout_token: &CsrfToken,
) -> Url {
    post_logout_redirect_uri
        .query_pairs_mut()
        .append_pair("destroy_session", "true");

    {
        let mut query_params = end_session_endpoint.query_pairs_mut();

        query_params.append_pair(
            "post_logout_redirect_uri",
            post_logout_redirect_uri.as_str(),
        );
        query_params.append_pair("destroy_session", "true");

        if let Some(id_token_hint) = id_token_hint {
            query_params.append_pair("id_token_hint", id_token_hint);
        }
        query_params.append_pair("state", logout_token.as_str());
    }
    end_session_endpoint
}
