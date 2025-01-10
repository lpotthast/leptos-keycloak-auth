use leptonic::components::prelude::*;
use leptos::prelude::*;

#[component]
pub fn Welcome() -> impl IntoView {
    let (count, set_count) = signal(0);

    view! {
        <div style=r#"
            height: 100%;
            width: 100%;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 1em;
            background-color: antiquewhite;
        "#>
            <h2>"Welcome to Leptonic"</h2>

            <span id="count" style="margin-top: 3em;">
                "Count: " { move || count.get() }
            </span>

            <Button attr:id="increase" on_press=move|_| set_count.update(|c| *c += 1)>
                "Increase"
            </Button>
        </div>
    }
}
