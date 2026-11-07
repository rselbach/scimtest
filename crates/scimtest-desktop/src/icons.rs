//! Icons drawn in the colour of the element that shows them.

use rune::Icon;

pub static EYE: Icon = Icon {
    name: "scimtest-eye",
    view: 16.0,
    body: r#"<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="M1 8s2.5-4.5 7-4.5S15 8 15 8s-2.5 4.5-7 4.5S1 8 1 8Z"/><circle fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" cx="8" cy="8" r="2"/>"#,
};
pub static USER: Icon = Icon {
    name: "scimtest-user",
    view: 16.0,
    body: r#"<circle fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" cx="8" cy="6" r="2.6"/><path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" d="M3 14c0-2.4 2.2-4 5-4s5 1.6 5 4"/>"#,
};
pub static USERS: Icon = Icon {
    name: "scimtest-users",
    view: 16.0,
    body: r#"<circle fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" cx="5" cy="6" r="2.2"/><circle fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" cx="11" cy="6" r="1.9"/><path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" d="M1.5 13c0-2 1.6-3.2 3.5-3.2s3.5 1.2 3.5 3.2M9 13c0-1.4 1-2.4 2.5-2.4s2.5 1 2.5 2.4"/>"#,
};
pub static ENVIRONMENTS: Icon = Icon {
    name: "scimtest-environments",
    view: 16.0,
    body: r#"<rect fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" x="2.5" y="3" width="11" height="10" rx="2"/><path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" d="M5.5 6h5M5.5 8.5h5"/>"#,
};
pub static EDIT: Icon = Icon {
    name: "scimtest-edit",
    view: 16.0,
    body: r#"<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="m11.5 2.5 2 2L5 13H3v-2zM10 4l2 2"/>"#,
};
pub static TRASH: Icon = Icon {
    name: "scimtest-trash",
    view: 16.0,
    body: r#"<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" d="M3 4h10M6 4V2.5h4V4M4.5 4l.6 9h5.8l.6-9M7 6.5v4M9 6.5v4"/>"#,
};
pub static CHEVRON_DOWN: Icon = Icon {
    name: "scimtest-chevron-down",
    view: 16.0,
    body: r#"<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="m4 6 4 4 4-4"/>"#,
};
pub static HISTORY: Icon = Icon {
    name: "scimtest-history",
    view: 16.0,
    body: r#"<circle fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" cx="8" cy="8" r="5.5"/><path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="M8 5v3.2l2 1.3"/>"#,
};
pub static RESTORE: Icon = Icon {
    name: "scimtest-restore",
    view: 16.0,
    body: r#"<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="M3 8a5 5 0 1 0 1.5-3.6M3 2.5v3h3"/>"#,
};
pub static CIRCLE_CHECK: Icon = Icon {
    name: "scimtest-circle-check",
    view: 16.0,
    body: r#"<circle fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" cx="8" cy="8" r="5.5"/><path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="m5.6 8.2 1.7 1.7 3.2-3.4"/>"#,
};
pub static CHEVRON_RIGHT: Icon = Icon {
    name: "scimtest-chevron-right",
    view: 16.0,
    body: r#"<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="m6 4 4 4-4 4"/>"#,
};
pub static SHIELD: Icon = Icon {
    name: "scimtest-shield",
    view: 16.0,
    body: r#"<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="M8 1.8 13 3.6v4c0 3-2.2 5.2-5 6.6-2.8-1.4-5-3.6-5-6.6v-4z"/>"#,
};
pub static PULSE: Icon = Icon {
    name: "scimtest-pulse",
    view: 16.0,
    body: r#"<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="M1.5 8h3l1.8-4 3 8 1.8-4h3.4"/>"#,
};
pub static TOOLS: Icon = Icon {
    name: "scimtest-tools",
    view: 16.0,
    body: r#"<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="m3 13 6-6M9.5 3.5a2.5 2.5 0 0 1 3 3L11 7.5 8.5 5z"/>"#,
};
pub static GLOBE: Icon = Icon {
    name: "scimtest-globe",
    view: 16.0,
    body: r#"<circle fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" cx="8" cy="8" r="5.8"/><ellipse fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" cx="8" cy="8" rx="2.6" ry="5.8"/><path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" d="M2.2 8h11.6"/>"#,
};
pub static LIFECYCLE: Icon = Icon {
    name: "scimtest-lifecycle",
    view: 16.0,
    body: r#"<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="M2.5 5h8l-2-2M13.5 11h-8l2 2"/>"#,
};
pub static ID_CARD: Icon = Icon {
    name: "scimtest-id-card",
    view: 16.0,
    body: r#"<rect fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" x="1.8" y="3.2" width="12.4" height="9.6" rx="2"/><circle fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" cx="5.6" cy="7.2" r="1.4"/><path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" d="M9 6.8h3M9 9.2h3M4 11.2h3"/>"#,
};
