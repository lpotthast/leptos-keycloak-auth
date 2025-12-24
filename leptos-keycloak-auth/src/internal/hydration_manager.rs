use leptos::prelude::*;

/// Manages hydration related state.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HydrationManager {
    /// True when we're in hydration.
    ///
    /// On the server, the hydration is always inactive (false).
    ///
    /// On the client, the hydration window is active (true) initially and becomes inactive after
    /// the first animation frame, ensuring hydration completes before auth state becomes observable.
    pub in_hydration_window: Signal<bool>,
}

impl HydrationManager {
    pub fn new() -> Self {
        #[cfg(feature = "ssr")]
        {
            // Server never in hydration window - it already returns Indeterminate state
            Self {
                in_hydration_window: Signal::from(false),
            }
        }

        #[cfg(not(feature = "ssr"))]
        {
            let (in_window, set_in_window) = signal(true);

            // Exit hydration window after first animation frame
            // This ensures hydration completes before auth state becomes observable
            request_animation_frame(move || {
                set_in_window.set(false);
            });

            Self {
                in_hydration_window: in_window.into(),
            }
        }
    }
}
