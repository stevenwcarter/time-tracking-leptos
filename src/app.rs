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
