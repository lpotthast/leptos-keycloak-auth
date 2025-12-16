use codee::{CodecError, Decoder, Encoder};
use leptos::prelude::{
    signal, Effect, Get, GetUntracked, LocalStorage, ReadSignal, Set, Signal, UpdateUntracked,
    WriteSignal,
};
use leptos_use::core::MaybeRwSignal;
use leptos_use::storage::{
    use_storage_with_options, StorageType, UseStorageError, UseStorageOptions,
};
use std::fmt::Debug;

pub(crate) struct UseStorageReturn<T, Remover>
where
    T: Send + Sync + 'static,
    Remover: Fn() + Clone + Send + Sync,
{
    pub(crate) read: Signal<T>,
    pub(crate) write: WriteSignal<T>,
    pub(crate) remove: Remover,

    #[expect(unused)]
    decode_err: (ReadSignal<bool>, WriteSignal<bool>),
    #[expect(unused)]
    effect: Effect<LocalStorage>,
}

pub(crate) fn use_storage_with_options_and_error_handler<T, C>(
    storage_type: StorageType,
    key: impl Into<Signal<String>> + 'static,
    // Read once on creation. Reused through cloning when a decode error must be resolved by using the initial value again.
    initial_value: impl Into<MaybeRwSignal<T>>,
) -> UseStorageReturn<T, impl Fn() + Clone + Send + Sync>
where
    T: Default + Debug + Clone + PartialEq + Send + Sync,
    C: Encoder<T, Encoded = String> + Decoder<T, Encoded = str>,
    <C as Encoder<T>>::Error: Debug,
    <C as Decoder<T>>::Error: Debug,
{
    let (decode_err, set_decode_err) = signal(false);

    let key = key.into();

    let initial_value_signal = initial_value.into();
    let initial_value = match &initial_value_signal {
        MaybeRwSignal::Static(s) => s.clone(),
        MaybeRwSignal::DynamicRw(r, _) | MaybeRwSignal::DynamicRead(r) => r.get_untracked(),
    };
    let options = UseStorageOptions::default()
        .initial_value(initial_value_signal)
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

    let (read, write, remove) = use_storage_with_options::<T, C>(storage_type, key, options);

    let remove_clone = remove.clone();
    let effect = Effect::new(move |_| {
        if decode_err.get() {
            tracing::trace!(
                "Removing previously persisted value of '{}' due to a decode error. Using initial value: {initial_value:?}",
                key.get()
            );
            remove_clone();
            write.set(initial_value.clone());
            set_decode_err.update_untracked(|it| *it = false);
        }
    });

    UseStorageReturn {
        read,
        write,
        remove,
        decode_err: (decode_err, set_decode_err),
        effect,
    }
}
