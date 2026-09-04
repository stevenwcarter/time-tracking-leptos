//! The per-project breakdown, including click-to-copy notes.

use leptos::either::Either;
use leptos::prelude::*;
use time_tracking_parser::{ProjectSummary, Time};

use crate::clipboard::copy_to_clipboard;

#[component]
pub fn ProjectItem(project: ProjectSummary) -> impl IntoView {
    let duration = format!(
        "{} ({} hrs)",
        Time::format_duration_minutes(project.total_minutes),
        Time::format_duration_decimal(project.total_minutes),
    );

    // Pre-rendered here rather than in the handler so the click path stays
    // allocation-free and the closure only needs to clone a finished string.
    let notes_for_clipboard = project
        .notes
        .iter()
        .map(|note| format!("- {note}"))
        .collect::<Vec<_>>()
        .join("\n");

    let name = project.name;
    let notes = project.notes;

    let note_rows = notes
        .iter()
        .map(|note| {
            view! {
                <p class="text-sm text-gray-600 flex items-start">
                    <span class="text-gray-400 mr-2 mt-0.5 text-xs">"-"</span>
                    <span>{note.clone()}</span>
                </p>
            }
        })
        .collect_view();

    // Absent, not hidden, when there are no notes — matches the Dioxus
    // original's `if !project.notes.is_empty() { div { ... } }`, which never
    // emits the wrapper at all.
    let notes_block =
        (!notes.is_empty()).then(|| view! { <div class="space-y-1">{note_rows}</div> });

    view! {
        <div
            class="bg-gray-50 rounded-lg p-4 border border-gray-200 cursor-pointer hover:bg-gray-100 transition-colors"
            on:click=move |_| copy_to_clipboard(notes_for_clipboard.clone())
        >
            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-3">
                <h4 class="text-base font-semibold text-gray-800">{name}</h4>
                <span class="text-sm font-medium text-blue-600 bg-blue-100 px-2 py-1 rounded-full mt-1 sm:mt-0">
                    {duration}
                </span>
            </div>
            {notes_block}
        </div>
    }
}

#[component]
pub fn ProjectsDisplay(projects: Vec<ProjectSummary>) -> impl IntoView {
    if projects.is_empty() {
        return Either::Left(view! {
            <div class="text-center py-8 text-gray-500">
                <p class="text-sm">
                    "No projects found. Enter your time tracking data to see the breakdown."
                </p>
            </div>
        });
    }

    let items = projects
        .into_iter()
        .map(|project| view! { <ProjectItem project=project/> })
        .collect_view();

    Either::Right(view! {
        <div>
            <h3 class="text-lg font-semibold text-gray-800 mb-4 border-b border-gray-200 pb-2">
                "Projects"
            </h3>
            <div class="space-y-4">{items}</div>
        </div>
    })
}
