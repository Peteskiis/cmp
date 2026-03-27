use std::io::stdout;

use crossterm::cursor::SetCursorStyle;
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget};

const INPUT_HEIGHT: u16 = 4;
const BG_DARK: Color = Color::Rgb(40, 44, 52);
const PROMPT_COLOR: Color = Color::Rgb(34, 199, 168);
const PLACEHOLDER_COLOR: Color = Color::Rgb(90, 90, 90);

/// RAII guard that restores the terminal on drop.
pub struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), SetCursorStyle::DefaultUserShape);
    }
}

pub type Term = Terminal<CrosstermBackend<std::io::Stdout>>;

/// Set up the inline terminal viewport.
pub fn init() -> anyhow::Result<(Term, RawModeGuard)> {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), SetCursorStyle::DefaultUserShape);
        original_hook(info);
    }));

    enable_raw_mode()?;
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

/// Draw the input widget in the inline viewport.
pub fn draw_input(terminal: &mut Term, input: &str, cursor_pos: usize) -> anyhow::Result<()> {
    terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

        let bg_style = Style::default().bg(BG_DARK);
        for &chunk in &[chunks[0], chunks[1], chunks[2]] {
            frame.render_widget(Paragraph::new("").style(bg_style), chunk);
        }

        let prompt = Span::styled(
            " \u{203a} ",
            Style::default()
                .fg(PROMPT_COLOR)
                .add_modifier(Modifier::BOLD),
        );
        let input_line = if input.is_empty() {
            Line::from(vec![
                prompt,
                Span::styled("Type a message...", Style::default().fg(PLACEHOLDER_COLOR)),
            ])
        } else {
            Line::from(vec![prompt, Span::raw(input)])
        };
        frame.render_widget(Paragraph::new(input_line).style(bg_style), chunks[1]);

        let footer = Line::from(vec![
            Span::styled("  Enter", Style::default().fg(Color::DarkGray)),
            Span::styled(" send  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Ctrl+D", Style::default().fg(Color::DarkGray)),
            Span::styled(" quit", Style::default().fg(Color::DarkGray)),
        ]);
        frame.render_widget(Paragraph::new(footer), chunks[3]);

        // cursor_pos is already adjusted for scroll by the caller
        // +3 for " › " prefix; terminal width naturally clips
        #[allow(clippy::cast_possible_truncation)] // cursor_pos bounded by visible input width
        let cursor_x = chunks[1].x + 3 + cursor_pos as u16;
        frame.set_cursor_position((
            cursor_x.min(chunks[1].right().saturating_sub(1)),
            chunks[1].y,
        ));
    })?;

    let _ = execute!(stdout(), SetCursorStyle::BlinkingBar);
    Ok(())
}

/// Insert a user message above the viewport.
pub fn insert_user_message(terminal: &mut Term, text: &str) -> anyhow::Result<()> {
    // "› " prefix = 2 chars
    let lines = wrap_message(text, terminal.size()?.width, 2);
    // height = message lines + 2 blank lines (above/below)
    #[allow(clippy::cast_possible_truncation)] // line count bounded by terminal height
    let height = (lines.len() + 2) as u16;

    terminal.insert_before(height, |buf| {
        Line::from("").render(Rect::new(buf.area.x, buf.area.y, buf.area.width, 1), buf);

        for (i, line_text) in lines.iter().enumerate() {
            let prefix = if i == 0 { "\u{203a} " } else { "  " };
            let line = Line::from(vec![
                Span::styled(
                    prefix,
                    Style::default().add_modifier(Modifier::BOLD | Modifier::DIM),
                ),
                Span::raw(line_text.as_str()),
            ]);
            #[allow(clippy::cast_possible_truncation)] // i bounded by terminal height
            let y = buf.area.y + 1 + i as u16;
            let area = Rect::new(buf.area.x, y, buf.area.width, 1);
            let bg = Style::default().bg(Color::Rgb(50, 54, 62));
            Paragraph::new(line).style(bg).render(area, buf);
        }

        #[allow(clippy::cast_possible_truncation)] // lines.len() bounded by terminal height
        let last_y = buf.area.y + 1 + lines.len() as u16;
        Line::from("").render(Rect::new(buf.area.x, last_y, buf.area.width, 1), buf);
    })?;

    Ok(())
}

/// Insert a friend's message above the viewport.
pub fn insert_friend_message(terminal: &mut Term, sender: &str, text: &str) -> anyhow::Result<()> {
    // "• {sender}: " prefix = 4 + sender.len()
    let lines = wrap_message(text, terminal.size()?.width, 4 + sender.len());
    #[allow(clippy::cast_possible_truncation)] // line count bounded by terminal height
    let height = (lines.len() + 2) as u16;

    terminal.insert_before(height, |buf| {
        Line::from("").render(Rect::new(buf.area.x, buf.area.y, buf.area.width, 1), buf);

        for (i, line_text) in lines.iter().enumerate() {
            let prefix = if i == 0 {
                format!("\u{2022} {sender}: ")
            } else {
                "  ".to_owned()
            };
            let line = Line::from(vec![
                Span::styled(prefix, Style::default().add_modifier(Modifier::DIM)),
                Span::raw(line_text.as_str()),
            ]);
            #[allow(clippy::cast_possible_truncation)] // i bounded by terminal height
            let y = buf.area.y + 1 + i as u16;
            let area = Rect::new(buf.area.x, y, buf.area.width, 1);
            line.render(area, buf);
        }

        #[allow(clippy::cast_possible_truncation)] // lines.len() bounded by terminal height
        let last_y = buf.area.y + 1 + lines.len() as u16;
        Line::from("").render(Rect::new(buf.area.x, last_y, buf.area.width, 1), buf);
    })?;

    Ok(())
}

/// Insert a status message.
pub fn insert_status(terminal: &mut Term, text: &str) -> anyhow::Result<()> {
    terminal.insert_before(1, |buf| {
        let line = Line::from(Span::styled(
            format!("  {text}"),
            Style::default().fg(Color::DarkGray),
        ));
        line.render(Rect::new(buf.area.x, buf.area.y, buf.area.width, 1), buf);
    })?;
    Ok(())
}

/// Simple word wrap respecting terminal width.
/// `prefix_width` is the number of characters used by the first-line prefix.
fn wrap_message(text: &str, width: u16, prefix_width: usize) -> Vec<String> {
    let max_width = (width as usize).saturating_sub(prefix_width);
    if max_width == 0 {
        return vec![text.to_owned()];
    }

    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
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
    if !current.is_empty() {
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
}
