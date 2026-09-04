use leptos::prelude::*;
use leptos_meta::{MetaTags, Stylesheet, Title, provide_meta_context};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;

use crate::components::time_display::TimeDisplay;
use crate::components::time_entry_area::TimeEntryArea;
use crate::storage::StorageKey;
use crate::storage::hook::use_persistent;

/// The SSR document shell. `HydrationScripts` injects the wasm loader.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <link rel="icon" href="/favicon.ico"/>
                <AutoReload options=options.clone()/>
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/time-tracking-leptos.css"/>
        <Title text="Time Tracker"/>
        <Router>
            <Routes fallback=NotFound>
                <Route path=path!("/") view=HomePage/>
            </Routes>
        </Router>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    let entry = use_persistent(StorageKey::TimeEntry);

    view! {
        <div class="min-h-screen bg-gray-50">
            <div class="w-full max-w-7xl mx-auto px-4 py-8">
                <div class="flex flex-col md:flex-row gap-6 w-full">
                    <TimeEntryArea entry=entry/>
                    <TimeDisplay entry=entry/>
                </div>
            </div>
        </div>
    }
}

#[component]
fn NotFound() -> impl IntoView {
    view! {
        <main class="min-h-screen flex items-center justify-center bg-gray-50">
            <p class="text-gray-600">"Page not found."</p>
        </main>
    }
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;

    /// Renders `App` exactly as the server would.
    ///
    /// `leptos_axum`'s handler provides the requested path as a `RequestUrl`
    /// context before rendering (see `leptos_axum::render_app_to_stream`);
    /// `<Router>` panics without it. We do the same for `"/"`, the only
    /// route this app defines, so the tree built here matches production.
    fn render_app() -> String {
        use leptos::prelude::*;
        use leptos_router::location::RequestUrl;

        let runtime = Owner::new();
        let html = runtime.with(|| {
            provide_context(RequestUrl::new("/"));
            view! { <App/> }.to_html()
        });
        runtime.cleanup();
        html
    }

    #[test]
    fn ssr_renders_chrome() {
        let html = render_app();
        assert!(html.contains("Time Entry"), "entry pane heading missing");
        assert!(
            html.contains("Time Summary"),
            "summary pane heading missing"
        );
        assert!(html.contains("How to use this tool"), "help toggle missing");
        assert!(
            html.contains("whitespace-pre-wrap"),
            "help sample block missing — it must be in the SSR'd HTML, not \
             mounted client-side, or hydration sees a different node count"
        );
    }

    /// Pins spec invariant I2. The server cannot know whether the user has
    /// saved data, so it must not render any conclusion that depends on it.
    #[test]
    fn ssr_omits_loaded_state() {
        let html = render_app();
        assert!(
            !html.contains("No projects found"),
            "server rendered the empty state it cannot know; returning users \
             would see it flash before their data loads (spec §5)"
        );
        assert!(
            !html.contains("hours)"),
            "server rendered a computed total; the summary must be blank \
             until localStorage is read (spec §5)"
        );
        assert!(
            !html.contains("No dead time"),
            "server rendered a dead-time conclusion (spec §5)"
        );
    }

    /// Pins spec invariant I4 for the one element whose SSR shape is subtle.
    #[test]
    fn ssr_textarea_is_empty() {
        let html = render_app();
        assert!(
            html.contains("<textarea") && html.contains("></textarea>"),
            "the SSR'd textarea must have no text content, so the hydrate-side \
             prop:value binding attaches to a matching node"
        );
    }
}
