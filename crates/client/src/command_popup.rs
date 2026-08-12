use crossterm::event::KeyCode;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::ui::ACCENT_COLOR;

const DESC_COLOR: Color = Color::DarkGray;

/// Column at which descriptions align.
const DESC_COL: usize = 20;

/// Metadata for one slash command.
struct CommandDef {
    name: &'static str,
    usage: &'static str,
    description: &'static str,
    has_args: bool,
}

const COMMANDS: &[CommandDef] = &[
    CommandDef {
        name: "chat",
        usage: "/chat <user>",
        description: "Start or switch conversation",
        has_args: true,
    },
    CommandDef {
        name: "notes",
        usage: "/notes",
        description: "Note to self",
        has_args: false,
    },
    CommandDef {
        name: "contacts",
        usage: "/contacts",
        description: "List all contacts",
        has_args: false,
    },
    CommandDef {
        name: "verify",
        usage: "/verify [confirm|clear]",
        description: "Show safety number",
        has_args: true,
    },
    CommandDef {
        name: "keys",
        usage: "/keys",
        description: "Show keyboard shortcuts",
        has_args: false,
    },
    CommandDef {
        name: "quit",
        usage: "/quit",
        description: "Exit",
        has_args: false,
    },
];

/// Action returned by [`CommandPopup::handle_key`] to tell the caller what to do.
pub(crate) enum PopupAction {
    /// Key was consumed by the popup (e.g. navigation). No further handling.
    Consumed,
    /// Complete the command into the input and dismiss the popup.
    Complete(String),
    /// Set the input text and then submit it (for arg-less commands).
    Submit(String),
    /// Dismiss the popup without changing input.
    Dismiss,
    /// The popup does not handle this key — fall through to normal input handling.
    PassThrough,
}

pub(crate) struct CommandPopup {
    filter: String,
    selected: usize,
    filtered_indices: Vec<usize>,
}

impl CommandPopup {
    pub(crate) fn new() -> Self {
        let filtered_indices: Vec<usize> = (0..COMMANDS.len()).collect();
        Self {
            filter: String::new(),
            selected: 0,
            filtered_indices,
        }
    }

    /// Update filter from current input. Returns `false` if the popup should be dismissed.
    pub(crate) fn sync(&mut self, input: &str) -> bool {
        let Some(after_slash) = input.strip_prefix('/') else {
            return false;
        };

        // Extract the command token (first whitespace-delimited word)
        let token = after_slash.split_whitespace().next().unwrap_or("");
        let has_space_after_token = after_slash.len() > token.len();

        // If user typed a space after an exact-match command with args, dismiss
        // so they can type the argument freely (e.g. "/chat alice")
        if has_space_after_token {
            let exact_match = COMMANDS.iter().any(|cmd| cmd.name == token && cmd.has_args);
            if exact_match {
                return false;
            }
        }

        token.clone_into(&mut self.filter);
        self.refilter();
        true
    }

    fn refilter(&mut self) {
        self.filtered_indices = COMMANDS
            .iter()
            .enumerate()
            .filter(|(_, cmd)| cmd.name.starts_with(self.filter.as_str()))
            .map(|(i, _)| i)
            .collect();

        // Clamp selection
        if self.filtered_indices.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.filtered_indices.len() {
            self.selected = self.filtered_indices.len() - 1;
        }
    }

    pub(crate) const fn move_up(&mut self) {
        if !self.filtered_indices.is_empty() {
            if self.selected == 0 {
                self.selected = self.filtered_indices.len() - 1;
            } else {
                self.selected -= 1;
            }
        }
    }

    pub(crate) const fn move_down(&mut self) {
        if !self.filtered_indices.is_empty() {
            self.selected = (self.selected + 1) % self.filtered_indices.len();
        }
    }

    fn selected_command(&self) -> Option<&CommandDef> {
        self.filtered_indices
            .get(self.selected)
            .map(|&i| &COMMANDS[i])
    }

    fn completion_text(&self) -> Option<String> {
        self.selected_command().map(|cmd| {
            if cmd.has_args {
                format!("/{} ", cmd.name)
            } else {
                format!("/{}", cmd.name)
            }
        })
    }

    /// Handle a key event. Returns a [`PopupAction`] telling the caller what to do.
    pub(crate) fn handle_key(&mut self, code: KeyCode) -> PopupAction {
        match code {
            KeyCode::Up => {
                self.move_up();
                PopupAction::Consumed
            }
            KeyCode::Down => {
                self.move_down();
                PopupAction::Consumed
            }
            KeyCode::Tab => self
                .completion_text()
                .map_or(PopupAction::Consumed, PopupAction::Complete),
            KeyCode::Enter => match self.selected_command() {
                Some(cmd) if cmd.has_args => self
                    .completion_text()
                    .map_or(PopupAction::PassThrough, PopupAction::Complete),
                Some(_) => self
                    .completion_text()
                    .map_or(PopupAction::PassThrough, PopupAction::Submit),
                None => PopupAction::PassThrough,
            },
            KeyCode::Esc => PopupAction::Dismiss,
            _ => PopupAction::PassThrough,
        }
    }

    /// Number of rows the popup needs for rendering.
    pub(crate) const fn row_count(&self) -> u16 {
        if self.filtered_indices.is_empty() {
            1 // "no matches" row
        } else {
            #[allow(clippy::cast_possible_truncation)]
            {
                self.filtered_indices.len() as u16
            }
        }
    }

    /// Render the popup into the given area.
    #[allow(clippy::cast_possible_truncation)] // row index bounded by area.height (u16)
    pub(crate) fn render(&self, area: Rect, buf: &mut Buffer) {
        if self.filtered_indices.is_empty() {
            let line = Line::from(Span::styled(
                "  no matches",
                Style::default()
                    .fg(DESC_COLOR)
                    .add_modifier(Modifier::ITALIC),
            ));
            if area.height > 0 {
                buf.set_line(area.x, area.y, &line, area.width);
            }
            return;
        }

        let width = area.width as usize;

        for (i, &cmd_idx) in self
            .filtered_indices
            .iter()
            .enumerate()
            .take(area.height as usize)
        {
            let cmd = &COMMANDS[cmd_idx];
            let is_selected = i == self.selected;
            let y = area.y + i as u16;

            let usage_str = format!("  {}", cmd.usage);
            let padding = if usage_str.len() < DESC_COL {
                " ".repeat(DESC_COL - usage_str.len())
            } else {
                " ".to_owned()
            };
            let desc = cmd.description;

            // Truncate if needed
            let total_len = usage_str.len() + padding.len() + desc.len();
            let desc_display = if total_len > width {
                let available = width.saturating_sub(usage_str.len() + padding.len());
                if available > 3 {
                    format!("{}...", &desc[..available - 3])
                } else {
                    String::new()
                }
            } else {
                desc.to_owned()
            };

            let line = if is_selected {
                let style = Style::default()
                    .fg(ACCENT_COLOR)
                    .add_modifier(Modifier::BOLD);
                Line::from(vec![
                    Span::styled(&usage_str, style),
                    Span::styled(&padding, style),
                    Span::styled(desc_display, style),
                ])
            } else {
                let desc_style = Style::default().fg(DESC_COLOR);
                Line::from(vec![
                    Span::raw(&usage_str),
                    Span::raw(&padding),
                    Span::styled(desc_display, desc_style),
                ])
            };

            buf.set_line(area.x, y, &line, area.width);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_empty_shows_all() {
        let mut popup = CommandPopup::new();
        assert!(popup.sync("/"));
        assert_eq!(popup.filtered_indices.len(), COMMANDS.len());
    }

    #[test]
    fn filter_prefix_narrows() {
        let mut popup = CommandPopup::new();
        assert!(popup.sync("/c"));
        assert_eq!(popup.filtered_indices.len(), 2); // chat, contacts
    }

    #[test]
    fn filter_exact_match() {
        let mut popup = CommandPopup::new();
        assert!(popup.sync("/quit"));
        assert_eq!(popup.filtered_indices.len(), 1);
        assert_eq!(popup.selected_command().unwrap().name, "quit");
    }

    #[test]
    fn filter_no_match() {
        let mut popup = CommandPopup::new();
        assert!(popup.sync("/xyz"));
        assert!(popup.filtered_indices.is_empty());
        assert!(popup.selected_command().is_none());
    }

    #[test]
    fn dismiss_when_typing_args() {
        let mut popup = CommandPopup::new();
        // "/chat alice" should dismiss because chat has_args and there's a space
        assert!(!popup.sync("/chat alice"));
    }

    #[test]
    fn no_dismiss_for_argless_with_space() {
        let mut popup = CommandPopup::new();
        // "/quit " should NOT dismiss because quit doesn't have has_args
        assert!(popup.sync("/quit "));
    }

    #[test]
    fn move_down_wraps() {
        let mut popup = CommandPopup::new();
        popup.sync("/");
        let count = popup.filtered_indices.len();
        for _ in 0..count {
            popup.move_down();
        }
        assert_eq!(popup.selected, 0); // wrapped back to first
    }

    #[test]
    fn move_up_wraps() {
        let mut popup = CommandPopup::new();
        popup.sync("/");
        popup.move_up(); // from 0 wraps to last
        assert_eq!(popup.selected, popup.filtered_indices.len() - 1);
    }

    #[test]
    fn completion_with_args_has_trailing_space() {
        let mut popup = CommandPopup::new();
        popup.sync("/chat");
        let text = popup.completion_text().unwrap();
        assert_eq!(text, "/chat ");
    }

    #[test]
    fn completion_without_args_no_trailing_space() {
        let mut popup = CommandPopup::new();
        popup.sync("/quit");
        let text = popup.completion_text().unwrap();
        assert_eq!(text, "/quit");
    }

    #[test]
    fn handle_key_escape_dismisses() {
        let mut popup = CommandPopup::new();
        popup.sync("/");
        assert!(matches!(
            popup.handle_key(KeyCode::Esc),
            PopupAction::Dismiss
        ));
    }

    #[test]
    fn handle_key_tab_completes() {
        let mut popup = CommandPopup::new();
        popup.sync("/");
        match popup.handle_key(KeyCode::Tab) {
            PopupAction::Complete(text) => assert_eq!(text, "/chat "),
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn handle_key_enter_submits_argless() {
        let mut popup = CommandPopup::new();
        popup.sync("/quit");
        match popup.handle_key(KeyCode::Enter) {
            PopupAction::Submit(text) => assert_eq!(text, "/quit"),
            _ => panic!("expected Submit"),
        }
    }

    #[test]
    fn handle_key_enter_completes_with_args() {
        let mut popup = CommandPopup::new();
        popup.sync("/chat");
        match popup.handle_key(KeyCode::Enter) {
            PopupAction::Complete(text) => assert_eq!(text, "/chat "),
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn row_count_all() {
        let popup = CommandPopup::new();
        assert_eq!(popup.row_count(), u16::try_from(COMMANDS.len()).unwrap());
    }

    #[test]
    fn row_count_no_matches() {
        let mut popup = CommandPopup::new();
        popup.sync("/xyz");
        assert_eq!(popup.row_count(), 1); // "no matches" row
    }

    #[test]
    fn selection_clamps_on_filter() {
        let mut popup = CommandPopup::new();
        popup.sync("/");
        // Select the last item
        popup.selected = COMMANDS.len() - 1;
        // Filter to fewer items
        popup.sync("/q");
        assert_eq!(popup.selected, 0); // clamped to new list size - 1 = 0
    }
}
