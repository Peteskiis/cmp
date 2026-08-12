use std::io::stdout;

use crossterm::cursor::SetCursorStyle;
use crossterm::event::{
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget};

const INPUT_HEIGHT: u16 = 40;
pub(crate) const PREFIX_WIDTH: usize = 3; // " › " or "   "
const BG_DARK: Color = Color::Rgb(40, 44, 52);
pub(crate) const ACCENT_COLOR: Color = Color::Rgb(34, 199, 168);
const PLACEHOLDER_COLOR: Color = Color::Rgb(90, 90, 90);

/// RAII guard that restores the terminal on drop.
pub(crate) struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = execute!(stdout(), crossterm::event::DisableBracketedPaste);
        let _ = execute!(stdout(), PopKeyboardEnhancementFlags);
        // Move cursor above the status bar / spacer lines so the clear
        // erases them too, not just the lines below the cursor.
        let _ = execute!(
            stdout(),
            crossterm::cursor::MoveUp(3), // spacer + status bar + top padding
            crossterm::style::ResetColor,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
            crossterm::terminal::Clear(crossterm::terminal::ClearType::FromCursorDown),
        );
        let _ = disable_raw_mode();
        println!();
        let _ = execute!(stdout(), SetCursorStyle::DefaultUserShape);
    }
}

pub(crate) type Term = Terminal<CrosstermBackend<std::io::Stdout>>;

/// Set up the inline terminal viewport.
pub(crate) fn init() -> anyhow::Result<(Term, RawModeGuard)> {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(stdout(), crossterm::event::DisableBracketedPaste);
        let _ = execute!(stdout(), PopKeyboardEnhancementFlags);
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), SetCursorStyle::DefaultUserShape);
        original_hook(info);
    }));

    enable_raw_mode()?;
    // Enable Kitty keyboard protocol so Shift+Enter is distinguishable from Enter.
    // Fails silently on terminals that don't support it — Ctrl+J works as fallback.
    let _ = execute!(
        stdout(),
        PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
    );
    // Enable bracketed paste so multi-line paste arrives as a single Event::Paste
    // instead of individual key events (which would trigger Enter = send).
    let _ = execute!(stdout(), crossterm::event::EnableBracketedPaste);
    let guard = RawModeGuard;

    let backend = CrosstermBackend::new(stdout());
    let terminal = Terminal::with_options(
        backend,
        ratatui::TerminalOptions {
            viewport: ratatui::Viewport::Inline(INPUT_HEIGHT),
        },
    )?;

    Ok((terminal, guard))
}

// ── Input wrapping helpers ──

/// Wrap input text for the input widget using character-level wrapping.
/// Returns `(visual_lines, line_start_char_indices)`.
pub(crate) fn wrap_input(input: &str, max_cols: usize) -> (Vec<String>, Vec<usize>) {
    if max_cols == 0 {
        return (vec![input.to_owned()], vec![0]);
    }

    let mut lines = Vec::new();
    let mut starts = Vec::new();
    let mut current = String::new();
    let mut line_start: usize = 0;
    let mut char_idx: usize = 0;

    for ch in input.chars() {
        if ch == '\n' {
            lines.push(std::mem::take(&mut current));
            starts.push(line_start);
            char_idx += 1;
            line_start = char_idx;
        } else {
            current.push(ch);
            char_idx += 1;
            if current.chars().count() >= max_cols {
                lines.push(std::mem::take(&mut current));
                starts.push(line_start);
                line_start = char_idx;
            }
        }
    }
    lines.push(current);
    starts.push(line_start);

    (lines, starts)
}

/// Map a cursor char index to visual `(row, col)`.
pub(crate) fn cursor_visual_pos(cursor_pos: usize, line_starts: &[usize]) -> (usize, usize) {
    for (i, &start) in line_starts.iter().enumerate().rev() {
        if cursor_pos >= start {
            return (i, cursor_pos - start);
        }
    }
    (0, cursor_pos)
}

/// Map visual `(row, col)` back to a cursor char index.
pub(crate) fn visual_to_cursor(
    row: usize,
    col: usize,
    line_starts: &[usize],
    lines: &[String],
) -> usize {
    if row >= lines.len() {
        let last = lines.len() - 1;
        return line_starts[last] + lines[last].chars().count();
    }
    let line_len = lines[row].chars().count();
    line_starts[row] + col.min(line_len)
}

/// Maximum number of input lines visible in the viewport.
/// Viewport rows minus spacer, status bar, top padding, bottom padding, and footer (5 rows).
pub(crate) const fn max_visible_input_lines() -> usize {
    (INPUT_HEIGHT as usize).saturating_sub(5)
}

/// Render a `ChatEntry` into display lines with optional background style.
/// Single source of truth for message rendering — used by both viewport and scrollback.
fn chat_entry_to_lines(
    entry: &crate::app::ChatEntry,
    width: u16,
) -> Vec<(Line<'static>, Option<Style>)> {
    let mut rows = Vec::new();
    match entry {
        crate::app::ChatEntry::Sent(text) => {
            let wrapped = wrap_message(text, width, 2);
            let sent_bg = Some(Style::default().bg(Color::Rgb(50, 54, 62)));
            rows.push((Line::from(""), None));
            for (i, lt) in wrapped.iter().enumerate() {
                let pfx = if i == 0 {
                    "\u{203a} ".to_owned()
                } else {
                    "  ".to_owned()
                };
                rows.push((
                    Line::from(vec![
                        Span::styled(
                            pfx,
                            Style::default().add_modifier(Modifier::BOLD | Modifier::DIM),
                        ),
                        Span::raw(lt.clone()),
                    ]),
                    sent_bg,
                ));
            }
            rows.push((Line::from(""), None));
        }
        crate::app::ChatEntry::Received { sender, text } => {
            let pw = 4 + sender.len();
            let wrapped = wrap_message(text, width, pw);
            rows.push((Line::from(""), None));
            for (i, lt) in wrapped.iter().enumerate() {
                let pfx = if i == 0 {
                    format!("\u{2022} {sender}: ")
                } else {
                    " ".repeat(pw)
                };
                rows.push((
                    Line::from(vec![
                        Span::styled(pfx, Style::default().add_modifier(Modifier::DIM)),
                        Span::raw(lt.clone()),
                    ]),
                    None,
                ));
            }
            rows.push((Line::from(""), None));
        }
        crate::app::ChatEntry::Status(text) => {
            rows.push((
                Line::from(Span::styled(
                    format!("  {text}"),
                    Style::default().fg(Color::DarkGray),
                )),
                None,
            ));
        }
        crate::app::ChatEntry::Tip(text) => {
            rows.push((
                Line::from(Span::styled(
                    format!("  {text}"),
                    Style::default().fg(Color::White),
                )),
                None,
            ));
        }
        crate::app::ChatEntry::Warning(text) => {
            rows.push((
                Line::from(Span::styled(
                    format!("  \u{26a0} {text}"),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )),
                None,
            ));
        }
    }
    rows
}

/// Flush chat entries that exceed the visible area to terminal scrollback.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn flush_chat_to_scrollback(
    terminal: &mut Term,
    history: &mut Vec<crate::app::ChatEntry>,
    max_chat_rows: usize,
) -> anyhow::Result<()> {
    if max_chat_rows == 0 || history.is_empty() {
        return Ok(());
    }

    let width = terminal.size()?.width;

    // Count display rows from the end (most recent), find where to cut
    let mut rows_from_end: usize = 0;
    let mut keep_from = 0;
    for (i, entry) in history.iter().enumerate().rev() {
        let entry_rows = chat_entry_to_lines(entry, width).len();
        if rows_from_end + entry_rows > max_chat_rows {
            keep_from = i + 1;
            break;
        }
        rows_from_end += entry_rows;
    }

    if keep_from == 0 {
        return Ok(());
    }

    // Flush oldest entries to scrollback via insert_before
    let to_flush: Vec<crate::app::ChatEntry> = history.drain(..keep_from).collect();
    for entry in &to_flush {
        let lines = chat_entry_to_lines(entry, width);
        #[allow(clippy::cast_possible_truncation)]
        let height = lines.len() as u16;
        if height == 0 {
            continue;
        }
        terminal.insert_before(height, |buf| {
            for (i, (line, bg)) in lines.iter().enumerate() {
                let y = buf.area.y + i as u16;
                let rect = Rect::new(buf.area.x, y, buf.area.width, 1);
                if let Some(style) = bg {
                    Paragraph::new(line.clone()).style(*style).render(rect, buf);
                } else {
                    line.clone().render(rect, buf);
                }
            }
        })?;
    }

    Ok(())
}

// ── Drawing ──

/// Draw chat history + input, top-aligned in the viewport.
#[allow(
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::cognitive_complexity
)]
pub(crate) fn draw_input(
    terminal: &mut Term,
    history: &[crate::app::ChatEntry],
    input_lines: &[String],
    cursor_row: usize,
    cursor_col: usize,
    scroll: usize,
    status_bar: &crate::status_bar::StatusBar,
    command_popup: Option<&crate::command_popup::CommandPopup>,
) -> anyhow::Result<()> {
    terminal.draw(|frame| {
        let area = frame.area();
        let bg_style = Style::default().bg(BG_DARK);

        let mut chat_rows: Vec<(Line<'_>, Option<Style>)> = Vec::new();
        for entry in history {
            chat_rows.extend(chat_entry_to_lines(entry, area.width));
        }

        // Input gets priority — as it grows, chat shrinks (scrolls up)
        let popup_height =
            command_popup.map_or(0_u16, crate::command_popup::CommandPopup::row_count);
        let footer_height = if popup_height > 0 {
            popup_height
        } else {
            1_u16
        };
        let input_height = (input_lines.len() as u16)
            .max(1)
            .min(area.height.saturating_sub(4 + footer_height));
        // non_chat = spacer(1) + status_bar(1) + top_pad(1) + input + bottom_pad(1) + footer
        let non_chat = 1 + 1 + 1 + input_height + 1 + footer_height;
        let chat_height = (chat_rows.len() as u16).min(area.height.saturating_sub(non_chat));

        let chunks = Layout::vertical([
            Constraint::Length(chat_height),
            Constraint::Length(1),             // spacer above status bar
            Constraint::Length(1),             // status bar
            Constraint::Length(1),             // top padding (dark bg)
            Constraint::Length(input_height),  // input
            Constraint::Length(1),             // bottom padding (dark bg)
            Constraint::Length(footer_height), // footer or popup
            Constraint::Min(0),                // empty
        ])
        .split(area);

        // Chat history
        let chat_area = chunks[0];
        let chat_skip = chat_rows.len().saturating_sub(chat_area.height as usize);
        for (i, (line, bg)) in chat_rows
            .iter()
            .skip(chat_skip)
            .take(chat_area.height as usize)
            .enumerate()
        {
            let y = chat_area.y + i as u16;
            let rect = Rect::new(chat_area.x, y, chat_area.width, 1);
            if let Some(style) = bg {
                Paragraph::new(line.clone())
                    .style(*style)
                    .render(rect, frame.buffer_mut());
            } else {
                line.clone().render(rect, frame.buffer_mut());
            }
        }

        // Status bar (no dark background — sits above the dark input area)
        // chunks[1] is an empty spacer line above the status bar
        status_bar.render(chunks[2], frame.buffer_mut());

        // Top padding (dark bg)
        frame.render_widget(Paragraph::new("").style(bg_style), chunks[3]);

        // Input lines
        let input_area = chunks[4];
        let visible_count = input_area.height as usize;

        for row in 0..input_area.height {
            let y = input_area.y + row;
            let rect = Rect::new(input_area.x, y, input_area.width, 1);
            frame.render_widget(Paragraph::new("").style(bg_style), rect);
        }

        for (i, line_text) in input_lines
            .iter()
            .skip(scroll)
            .take(visible_count)
            .enumerate()
        {
            let line_idx = scroll + i;
            let prefix = if i == 0 {
                Span::styled(
                    " \u{203a} ",
                    Style::default()
                        .fg(ACCENT_COLOR)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("   ", bg_style)
            };

            let content = if line_idx == 0 && line_text.is_empty() && input_lines.len() == 1 {
                Line::from(vec![
                    prefix,
                    Span::styled("Type a message...", Style::default().fg(PLACEHOLDER_COLOR)),
                ])
            } else {
                Line::from(vec![prefix, Span::raw(line_text.as_str())])
            };

            let y = input_area.y + i as u16;
            let rect = Rect::new(input_area.x, y, input_area.width, 1);
            frame.render_widget(Paragraph::new(content).style(bg_style), rect);
        }

        // Bottom padding
        frame.render_widget(Paragraph::new("").style(bg_style), chunks[5]);

        // Footer or command popup
        if let Some(popup) = command_popup {
            popup.render(chunks[6], frame.buffer_mut());
        } else {
            let footer = Line::from(vec![
                Span::styled("  Enter", Style::default().fg(Color::DarkGray)),
                Span::styled(" send  ", Style::default().fg(Color::DarkGray)),
                Span::styled("Shift+Enter", Style::default().fg(Color::DarkGray)),
                Span::styled(" newline  ", Style::default().fg(Color::DarkGray)),
                Span::styled("Ctrl+D", Style::default().fg(Color::DarkGray)),
                Span::styled(" quit", Style::default().fg(Color::DarkGray)),
            ]);
            frame.render_widget(Paragraph::new(footer), chunks[6]);
        }

        // Cursor
        let cursor_visible_row = cursor_row.saturating_sub(scroll);
        let cursor_x = input_area.x + PREFIX_WIDTH as u16 + cursor_col as u16;
        let cursor_y = input_area.y + cursor_visible_row as u16;
        frame.set_cursor_position((
            cursor_x.min(input_area.right().saturating_sub(1)),
            cursor_y.min(input_area.bottom().saturating_sub(1)),
        ));
    })?;

    let _ = execute!(stdout(), SetCursorStyle::BlinkingBar);
    Ok(())
}

/// Word wrap respecting terminal width and explicit newlines.
/// `prefix_width` is the number of characters used by the first-line prefix.
fn wrap_message(text: &str, width: u16, prefix_width: usize) -> Vec<String> {
    let max_width = (width as usize).saturating_sub(prefix_width);
    if max_width == 0 {
        return vec![text.to_owned()];
    }

    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            if current.is_empty() {
                word.clone_into(&mut current);
            } else if current.len() + 1 + word.len() <= max_width {
                current.push(' ');
                current.push_str(word);
            } else {
                lines.push(current);
                current = String::new();
                word.clone_into(&mut current);
            }
        }
        // Always push one line per paragraph (empty for blank lines)
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── wrap_message tests ──

    #[test]
    fn wrap_empty_string() {
        let result = wrap_message("", 80, 4);
        assert_eq!(result, vec![""]);
    }

    #[test]
    fn wrap_single_short_word() {
        let result = wrap_message("hello", 80, 4);
        assert_eq!(result, vec!["hello"]);
    }

    #[test]
    fn wrap_fits_in_one_line() {
        let result = wrap_message("hello world", 80, 4);
        assert_eq!(result, vec!["hello world"]);
    }

    #[test]
    fn wrap_splits_long_text() {
        // width=20, minus 4 prefix = 16 chars max per line
        let result = wrap_message("the quick brown fox jumps over the lazy dog", 20, 4);
        assert!(result.len() > 1);
        for line in &result {
            assert!(line.len() <= 16, "line too long: {line}");
        }
    }

    #[test]
    fn wrap_single_word_longer_than_width() {
        // A single word that exceeds max_width stays on one line (no mid-word break)
        let result = wrap_message("superlongwordthatexceedswidth", 10, 4);
        assert_eq!(result, vec!["superlongwordthatexceedswidth"]);
    }

    #[test]
    fn wrap_zero_width() {
        let result = wrap_message("hello", 0, 4);
        assert_eq!(result, vec!["hello"]);
    }

    #[test]
    fn wrap_width_4_leaves_zero_for_text() {
        // width=4 means max_width=0 after subtracting prefix
        let result = wrap_message("hello", 4, 4);
        assert_eq!(result, vec!["hello"]);
    }

    #[test]
    fn wrap_message_respects_newlines() {
        let result = wrap_message("line1\nline2\nline3", 80, 4);
        assert_eq!(result, vec!["line1", "line2", "line3"]);
    }

    #[test]
    fn wrap_message_blank_line_preserved() {
        let result = wrap_message("above\n\nbelow", 80, 4);
        assert_eq!(result, vec!["above", "", "below"]);
    }

    // ── wrap_input tests ──

    #[test]
    fn wrap_input_single_line() {
        let (lines, starts) = wrap_input("hello", 20);
        assert_eq!(lines, vec!["hello"]);
        assert_eq!(starts, vec![0]);
    }

    #[test]
    fn wrap_input_character_wrap() {
        let (lines, starts) = wrap_input("abcdefghij", 7);
        assert_eq!(lines, vec!["abcdefg", "hij"]);
        assert_eq!(starts, vec![0, 7]);
    }

    #[test]
    fn wrap_input_explicit_newline() {
        let (lines, starts) = wrap_input("hello\nworld", 20);
        assert_eq!(lines, vec!["hello", "world"]);
        assert_eq!(starts, vec![0, 6]);
    }

    #[test]
    fn wrap_input_empty() {
        let (lines, starts) = wrap_input("", 20);
        assert_eq!(lines, vec![""]);
        assert_eq!(starts, vec![0]);
    }

    #[test]
    fn wrap_input_newline_at_end() {
        let (lines, starts) = wrap_input("hello\n", 20);
        assert_eq!(lines, vec!["hello", ""]);
        assert_eq!(starts, vec![0, 6]);
    }

    #[test]
    fn wrap_input_zero_width() {
        let (lines, starts) = wrap_input("hello", 0);
        assert_eq!(lines, vec!["hello"]);
        assert_eq!(starts, vec![0]);
    }

    // ── cursor_visual_pos tests ──

    #[test]
    fn cursor_pos_start() {
        assert_eq!(cursor_visual_pos(0, &[0]), (0, 0));
    }

    #[test]
    fn cursor_pos_mid_first_line() {
        assert_eq!(cursor_visual_pos(3, &[0, 7]), (0, 3));
    }

    #[test]
    fn cursor_pos_second_line() {
        assert_eq!(cursor_visual_pos(8, &[0, 7]), (1, 1));
    }

    #[test]
    fn cursor_pos_at_wrap_boundary() {
        // Cursor at position 7, line starts at [0, 7]
        assert_eq!(cursor_visual_pos(7, &[0, 7]), (1, 0));
    }

    // ── visual_to_cursor tests ──

    #[test]
    fn visual_to_cursor_start() {
        assert_eq!(visual_to_cursor(0, 0, &[0], &["hello".into()]), 0);
    }

    #[test]
    fn visual_to_cursor_mid() {
        assert_eq!(visual_to_cursor(0, 3, &[0], &["hello".into()]), 3);
    }

    #[test]
    fn visual_to_cursor_second_line() {
        assert_eq!(
            visual_to_cursor(1, 2, &[0, 7], &["abcdefg".into(), "hij".into()]),
            9
        );
    }

    #[test]
    fn visual_to_cursor_clamps_to_line_end() {
        // Col 10 on a 5-char line → clamp to col 5 (end of line)
        assert_eq!(visual_to_cursor(0, 10, &[0], &["hello".into()]), 5);
    }

    #[test]
    fn visual_to_cursor_past_last_line() {
        assert_eq!(visual_to_cursor(5, 0, &[0], &["hello".into()]), 5);
    }
}
