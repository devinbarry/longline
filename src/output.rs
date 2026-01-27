use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Attribute, Cell, Color,
    ContentArrangement, Table,
};

use crate::policy;
use crate::types::Decision;

/// Map a Decision to its display color.
fn decision_color(d: Decision) -> Color {
    match d {
        Decision::Allow => Color::Green,
        Decision::Ask => Color::Yellow,
        Decision::Deny => Color::Red,
    }
}

/// Create a colored Cell for a Decision value.
fn decision_cell(d: Decision) -> Cell {
    Cell::new(d).fg(decision_color(d))
}
