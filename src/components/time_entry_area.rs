//! The left-hand entry pane: the textarea and the collapsible help.

use leptos::prelude::*;

use crate::storage::hook::Persistent;

const PLACEHOLDER: &str = "Enter your time tracking data here...\n\nExample:\n11:45-12:15 code1\n- Comment explaining what you did\n12:15-1:30 code2\n- Comment about what you were doing\n1:30-2 code1\n2-4 code3";

const SAMPLE: &str = "11:45-12:15 code1\n- Comment explaining what you did\n12:15-1:30 code2\n- Comment about what you were doing\n1:30-2 code1\n2-4 code3";

#[component]
pub fn TimeEntryArea(entry: Persistent) -> impl IntoView {
    view! {
        <div class="w-full md:w-1/2 bg-white rounded-lg shadow-sm border border-gray-200">
            <div class="p-6">
                <div class="flex justify-between items-center mb-4">
                    <h2 class="text-xl font-semibold text-gray-800">"Time Entry"</h2>
                    <button
                        class="px-3 py-1 text-sm bg-red-500 text-white rounded hover:bg-red-600 transition-colors"
                        on:click=move |_| entry.clear()
                    >
                        "Clear"
                    </button>
                </div>
                <textarea
                    id="time-entry-input"
                    class="w-full h-64 p-3 border border-gray-300 rounded-md resize-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors placeholder-gray-500 text-sm font-mono"
                    placeholder=PLACEHOLDER
                    // `prop:` rather than an attribute: a textarea's value is
                    // not reflected as an attribute after first render. Leptos
                    // does not serialize props into SSR output, so the server
                    // emits an empty textarea and hydration matches it.
                    prop:value=move || entry.get().unwrap_or_default()
                    on:input=move |ev| entry.set(event_target_value(&ev))
                ></textarea>
                <HelpSection/>
            </div>
        </div>
    }
}

#[component]
fn HelpSection() -> impl IntoView {
    let (show_help, set_show_help) = signal(false);

    view! {
        <div class="mt-4">
            <button
                class="flex items-center text-sm text-blue-600 hover:text-blue-800 transition-colors"
                on:click=move |_| set_show_help.update(|shown| *shown = !*shown)
            >
                <span class="mr-1">{move || if show_help.get() { "▼" } else { "▶" }}</span>
                "How to use this tool"
            </button>
            // Toggled by class rather than <Show> so the node count stays
            // constant and the help text is present in the SSR'd HTML.
            <div
                class="mt-3 p-4 bg-blue-50 rounded-lg border border-blue-200"
                class:hidden=move || !show_help.get()
            >
                <p class="text-sm text-gray-700 mb-3">
                    "You should enter your time in the format shown below. \"code1\" and \"code2\" can be anything you'd like, and the time will be aggregated together, even if you work on other time codes in the interim. You can try copying the data below into the text area to see a sample report. From the report, you can then note the time and copy the comments into the notes field in your time tracker."
                </p>
                <pre class="text-sm font-mono bg-gray-100 p-3 rounded border text-gray-800 whitespace-pre-wrap">
                    {SAMPLE}
                </pre>
            </div>
        </div>
    }
}
