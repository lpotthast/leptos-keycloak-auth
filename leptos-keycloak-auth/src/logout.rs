use crate::config::Options;
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

        let mut post_logout_redirect_url = options.read_value().post_logout_redirect_url.get();
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
