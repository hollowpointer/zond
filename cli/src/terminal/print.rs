// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::{cell::Cell, fmt::Display};

use crate::terminal::{banner, colors};
use colored::*;
use tracing::info;
use unicode_width::UnicodeWidthStr;

pub const TOTAL_WIDTH: usize = 64;

thread_local! {
    pub static GLOBAL_KEY_WIDTH: Cell<usize> = const { Cell::new(0) }
}

#[macro_export]
macro_rules! mprint {
    () => {
        $crate::print::print("");
    };
    ($msg:expr) => {
        $crate::print::print($msg);
    };
}

pub trait WithDefaultColor {
    fn with_default(self, default_color: Color) -> ColoredString;
}

impl WithDefaultColor for &str {
    fn with_default(self, default_color: Color) -> ColoredString {
        self.color(default_color)
    }
}

impl WithDefaultColor for String {
    fn with_default(self, default_color: Color) -> ColoredString {
        self.color(default_color)
    }
}

impl WithDefaultColor for ColoredString {
    fn with_default(self, _default_color: Color) -> ColoredString {
        self
    }
}

pub fn print(msg: &str) {
    info!(target: "zond::print", raw_msg = msg);
}

pub fn banner(no_banner: bool, q_level: u8) {
    if no_banner || q_level > 0 {
        return;
    }

    let text_content: String = format!("⟦ ZOND v{} ⟧ ", env!("CARGO_PKG_VERSION"));
    let text_width: usize = UnicodeWidthStr::width(text_content.as_str());
    let text: ColoredString = text_content.bright_green().bold();
    let sep: ColoredString = "═"
        .repeat(TOTAL_WIDTH.saturating_sub(text_width) / 2)
        .bright_black();
    let output: String = format!("{}{}{}", sep, text, sep);

    print(&output);
    banner::print();
}

pub fn header(msg: &str, q_level: u8) {
    if q_level > 0 {
        return;
    }

    let formatted: String = format!("⟦ {} ⟧", msg);
    let msg_len: usize = formatted.chars().count();

    let dash_count: usize = TOTAL_WIDTH.saturating_sub(msg_len);
    let left: usize = dash_count / 2;
    let right: usize = dash_count - left;

    let line: ColoredString = format!(
        "{}{}{}",
        "─".repeat(left),
        formatted.to_uppercase().bright_green(),
        "─".repeat(right)
    )
    .bright_black();

    print(&format!("{}", line));
}

pub fn fat_separator() {
    let sep: ColoredString = "═".repeat(TOTAL_WIDTH).bright_black();
    print(&format!("{}", sep));
}

pub fn aligned_line<V>(key: &str, value: V)
where
    V: Display + WithDefaultColor,
{
    let whitespace: String = ".".repeat((GLOBAL_KEY_WIDTH.get() + 1).saturating_sub(key.len()));
    let colon: String = format!(
        "{}{}",
        whitespace.color(colors::SEPARATOR),
        ":".color(colors::SEPARATOR)
    );
    let value: ColoredString = value.with_default(colors::TEXT_DEFAULT);
    print_status(format!("{}{} {}", key.color(colors::PRIMARY), colon, value));
}

pub fn print_status<T: AsRef<str>>(msg: T) {
    let prefix: ColoredString = ">".color(colors::SEPARATOR);
    let message: String = format!("{} {}", prefix, msg.as_ref().color(colors::TEXT_DEFAULT));
    print(&message);
}

pub fn tree_head(idx: usize, name: &str) {
    let idx_str: String = format!("[{}]", idx.to_string().color(colors::ACCENT));
    let output: String = format!(
        "{} {}",
        idx_str.color(colors::SEPARATOR),
        name.color(colors::PRIMARY)
    );
    print(&output);
}

pub fn as_tree(detail: Vec<(String, ColoredString)>) {
    let padding_width: usize = "Hostname".len();

    for (i, (key, value)) in detail.iter().enumerate() {
        let last: bool = i + 1 == detail.len();
        let branch: ColoredString = if !last { "├─" } else { "└─" }.bright_black();

        let dots_count: usize = padding_width.saturating_sub(key.len());
        let dots: ColoredString = ".".repeat(dots_count).color(colors::SEPARATOR);

        let output: String = format!(
            " {} {}{}{} {}",
            branch,
            key.color(colors::TEXT_DEFAULT),
            dots,
            ":".color(colors::SEPARATOR),
            value
        );

        print(&output);
    }
}

pub fn centerln(msg: &str) {
    let space = " ".repeat((TOTAL_WIDTH - console::measure_text_width(msg)) / 2);
    print(&format!("{}{}{}", space, msg, space));
}

pub fn no_results_banner() {
    print(&format!("{}", banner::NO_RESULTS_0.red().bold()));
}

pub fn end_of_program() {
    print(&format!(
        "{}",
        "═".repeat(TOTAL_WIDTH).color(colors::SEPARATOR)
    ));
}
