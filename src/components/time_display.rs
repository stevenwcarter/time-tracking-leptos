//! The right-hand summary panel.

use leptos::either::Either;
use leptos::prelude::*;
use time_tracking_parser::parse_time_tracking_data;

use crate::components::projects::ProjectsDisplay;
use crate::components::summary::{
    DeadTimeDisplay, SummarySkeleton, TimeOverview, WarningsDisplay, WorkingTimeDisplay,
};
use crate::storage::hook::Persistent;

#[component]
pub fn TimeDisplay(entry: Persistent) -> impl IntoView {
    view! {
        <div class="w-full md:w-1/2 bg-white rounded-lg shadow-sm border border-gray-200">
            <div class="p-6">
                <h2 class="text-xl font-semibold text-gray-800 mb-6">"Time Summary"</h2>
                {move || match entry.get() {
                    // Storage not read yet — blank slots, no claims. See spec §5.
                    None => Either::Left(view! { <SummarySkeleton/> }),
                    Some(text) => Either::Right(view! { <SummaryBody text=text/> }),
                }}
            </div>
        </div>
    }
}

/// Parses `text` and renders the full breakdown.
///
/// Reparsing on every keystroke replaces the Dioxus build's per-field memos.
/// The input is a single textarea's worth of text and the parser is pure, so
/// the simpler shape costs nothing measurable.
#[component]
fn SummaryBody(text: String) -> impl IntoView {
    let data = parse_time_tracking_data(&text);

    // Formatting borrows `data`, so all of it happens before the field moves.
    let start_time = data.formatted_start_time();
    let end_time = data.formatted_end_time();
    let total = data.formatted_total_minutes();
    let total_decimal = data.formatted_total_decimal();
    let dead = data.formatted_dead_time_minutes();
    let dead_decimal = data.formatted_dead_decimal();
    let dead_minutes = data.dead_time_minutes;
    let warnings = data.warnings;
    let projects = data.projects;

    view! {
        <TimeOverview start_time=start_time end_time=end_time/>
        <WorkingTimeDisplay total=total total_decimal=total_decimal/>
        <DeadTimeDisplay dead_minutes=dead_minutes dead=dead dead_decimal=dead_decimal/>
        <WarningsDisplay warnings=warnings/>
        <ProjectsDisplay projects=projects/>
    }
}

#[cfg(test)]
mod tests {
    use time_tracking_parser::parse_time_tracking_data;

    /// Pins spec invariant I3. The `Some("")` branch renders the output of
    /// this call, so the parser must be total over empty input and must report
    /// genuinely-empty results rather than, say, a spurious warning.
    #[test]
    fn empty_parse_is_total() {
        let data = parse_time_tracking_data("");
        assert_eq!(data.total_minutes, 0);
        assert_eq!(data.dead_time_minutes, 0);
        assert!(data.projects.is_empty(), "empty input yields no projects");
        assert!(data.warnings.is_empty(), "empty input yields no warnings");
    }
}
