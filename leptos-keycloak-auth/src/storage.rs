use std::{
    fmt::Debug,
    sync::{Arc, LazyLock},
};

use codee::{CodecError, Decoder, Encoder};
use leptos::prelude::*;
use leptos_use::storage::{
    StorageType, UseStorageError, UseStorageOptions, use_storage_with_options,
};

pub(crate) struct UseStorageReturn<T, Remover>
where
    T: Send + Sync + 'static,
    Remover: Fn() + Clone + Send + Sync,
{
    pub(crate) read: Signal<T>,
    pub(crate) write: Callback<T>,
    pub(crate) remove: Remover,

    #[expect(unused)]
    decode_err: (ReadSignal<bool>, WriteSignal<bool>),
}

/// # Params
/// - `initial_value_provider` - Lazy evaluated initial value. Only computed when necessary.
pub(crate) fn use_storage_with_options_and_error_handler<T, C>(
    storage_type: StorageType,
    key: impl Into<Signal<String>> + 'static,
    initial_value_provider: impl FnOnce() -> T + Send + 'static,
) -> UseStorageReturn<T, impl Fn() + Clone + Send + Sync>
where
    T: Debug + Clone + PartialEq + Send + Sync,
    C: Encoder<Option<T>, Encoded = String> + Decoder<Option<T>, Encoded = str>,
    <C as Encoder<Option<T>>>::Error: Debug,
    <C as Decoder<Option<T>>>::Error: Debug,
{
    let key = key.into();

    let initial_value: LazyLock<T, _> = LazyLock::new(initial_value_provider);
    let initial_value = Arc::new(initial_value);

    let (decode_err, set_decode_err) = signal(false);

    let options = UseStorageOptions::<Option<T>, _, _>::default()
        .initial_value(None)
        .listen_to_storage_changes(true)
        .delay_during_hydration(false)
        .on_error(move |err| {
            let log_as_error = match &err {
                UseStorageError::StorageNotAvailable(_)
                | UseStorageError::StorageReturnedNone
                | UseStorageError::GetItemFailed(_)
                | UseStorageError::SetItemFailed(_)
                | UseStorageError::RemoveItemFailed(_)
                | UseStorageError::NotifyItemChangedFailed(_) => true,
                UseStorageError::ItemCodecError(codec_err) => match codec_err {
                    CodecError::Encode(_) => true,
                    CodecError::Decode(_decode_err) => {
                        // Only schedule deletion (and log) once!
                        // We saw that these decode errors may come in multiple times in quick
                        // succession, without our effect being able to handle it in between.
                        if !decode_err.get_untracked() {
                            // Note: A "decode" error will always come up if we break the
                            // type, e.g. by adding a new field that wasn't previously
                            // persisted.
                            tracing::debug!(?err, "Data format of '{}' changed. Scheduling removal of previously persisted value.", key.get());
                            set_decode_err.set(true);
                        }
                        false
                    }
                },
            };
            if log_as_error {
                tracing::error!(?err, "Error reading '{}' from storage.", key.get());
            }
        });

    let storage_type_identifier = match storage_type {
        StorageType::Local => "Local",
        StorageType::Session => "Session",
        StorageType::Custom(_) => "Custom",
    };

    let (read, write, remove) =
        use_storage_with_options::<Option<T>, C>(storage_type, key, options);

    let initial_value_clone = initial_value.clone();
    if read.read_untracked().is_none() {
        tracing::trace!(
            "No '{}' found in {storage_type_identifier} storage. Setting initial value.",
            key.read_untracked(),
        );
        write.set(Some((*initial_value_clone).clone()));
    }

    let remove_clone = remove.clone();
    let initial_value_clone = initial_value.clone();
    Effect::new(move |_| {
        if decode_err.get() {
            let initial_value = (*initial_value_clone).clone();
            tracing::trace!(
                "Removing previously persisted value of '{}' due to a decode error. Using initial value: {initial_value:?}",
                key.get()
            );
            remove_clone();
            write.set(Some(initial_value));
            set_decode_err.update_untracked(|it| *it = false);
        }
    });

    let initial_value_clone = initial_value.clone();
    UseStorageReturn {
        // We use Memo instead of Signal to achieve lazy evaluation.
        read: Memo::new(move |_| read.get().unwrap_or_else(|| (*initial_value_clone).clone()))
            .into(),
        write: Callback::new(move |new| write.set(Some(new))),
        remove,
        decode_err: (decode_err, set_decode_err),
    }
}
