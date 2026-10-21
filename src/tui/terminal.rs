use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use std::io::{self, Stdout};
use std::sync::{Mutex, OnceLock};

type UiTerminal = Terminal<CrosstermBackend<Stdout>>;
static TERMINAL: OnceLock<Mutex<UiTerminal>> = OnceLock::new();

fn terminal() -> Option<&'static Mutex<UiTerminal>> {
    TERMINAL.get()
}

pub(crate) struct TerminalSession;

impl TerminalSession {
    pub(crate) fn new() -> io::Result<Self> {
        let term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        let _ = TERMINAL.set(Mutex::new(term));
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen, Hide) {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
            return Err(error);
        }
        match terminal()
            .ok_or_else(|| io::Error::other("terminal unavailable"))?
            .lock()
            .map_err(|_| io::Error::other("terminal lock poisoned"))?
            .clear()
        {
            Ok(()) => Ok(Self),
            Err(error) => {
                let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
                Err(error)
            }
        }
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        if let Some(term) = TERMINAL.get()
            && let Ok(mut term) = term.lock()
        {
            let _ = term.show_cursor();
        }
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
    }
}

pub(crate) fn clear() {
    if let Some(term) = TERMINAL.get()
        && let Ok(mut term) = term.lock()
    {
        let _ = term.clear();
    }
}

pub(crate) fn draw_content(title: &str, lines: &[Line<'static>], prompt: bool) {
    let Some(term) = terminal() else { return };
    let Ok(mut term) = term.lock() else { return };
    let _ = term.draw(|frame| {
        let area = frame.area();
        if too_small(area) {
            frame.render_widget(
                Paragraph::new("Terminal too small. Resize to at least 20 x 6.")
                    .wrap(Wrap { trim: true }),
                area,
            );
            return;
        }
        let (title_area, body_area, _) = content_layout(area, prompt);
        let content_width = body_area.width;
        let content_x = body_area.x;
        frame.render_widget(
            Paragraph::new(Line::styled(
                title.to_owned(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Rect::new(content_x, title_area.y, content_width, title_area.height),
        );
        let content = Paragraph::new(lines.to_vec())
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
        frame.render_widget(content, body_area);
    });
}

fn content_layout(area: Rect, prompt: bool) -> (Rect, Rect, Option<Rect>) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(if prompt { 1 } else { 0 }),
        ])
        .split(area);
    let width = area.width.min((super::INNER_WIDTH + 2) as u16);
    let x = area.x + area.width.saturating_sub(width) / 2;
    let centered = |r: Rect| Rect::new(x, r.y, width, r.height);
    (
        centered(chunks[0]),
        centered(chunks[1]),
        prompt.then(|| centered(chunks[2])),
    )
}

pub(crate) fn select_menu(title: &str, subtitle: &str, items: &[(&str, &str, &str)]) -> String {
    let mut selected = 0usize;
    let _raw = match RawMode::enable() {
        Ok(raw) => raw,
        Err(_) => return "0".into(),
    };
    let _ = execute!(io::stdout(), Hide);
    loop {
        let Some(term) = terminal() else {
            return "0".into();
        };
        let Ok(mut term) = term.lock() else {
            return "0".into();
        };
        let _ = term.draw(|frame| render_menu(frame, title, subtitle, items, &mut selected));
        drop(term);
        match event::read() {
            Ok(Event::Resize(_, _)) => {}
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    move_selection(&mut selected, items.len(), false)
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    move_selection(&mut selected, items.len(), true)
                }
                KeyCode::Enter => {
                    return items
                        .get(selected)
                        .map(|item| item.0.to_owned())
                        .unwrap_or_else(|| "0".into());
                }
                KeyCode::Esc | KeyCode::Backspace => return "0".into(),
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    if let Some(item) = items.iter().find(|item| item.0 == c.to_string()) {
                        return item.0.to_owned();
                    }
                }
                _ => {}
            },
            Ok(_) => {}
            Err(_) => return "0".into(),
        }
    }
}

fn render_menu(
    frame: &mut ratatui::Frame<'_>,
    title: &str,
    subtitle: &str,
    items: &[(&str, &str, &str)],
    selected: &mut usize,
) {
    use super::sanitize_terminal_text;
    let area = frame.area();
    if too_small(area) {
        frame.render_widget(
            Paragraph::new("Terminal too small. Resize to at least 20 x 6."),
            area,
        );
        return;
    }
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);
    frame.render_widget(
        Paragraph::new(Line::styled(
            sanitize_terminal_text(title),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        layout[0],
    );
    frame.render_widget(
        Paragraph::new(sanitize_terminal_text(subtitle))
            .style(Style::default().fg(Color::Gray))
            .wrap(Wrap { trim: true }),
        layout[1],
    );
    let list_items = items
        .iter()
        .map(|(key, name, desc)| {
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(format!("{key}  "), Style::default().fg(Color::Cyan)),
                    Span::styled(
                        sanitize_terminal_text(name),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::styled(
                    format!("   {}", sanitize_terminal_text(desc)),
                    Style::default().fg(Color::Gray),
                ),
            ])
        })
        .collect::<Vec<_>>();
    let list = List::new(list_items)
        .highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White))
        .highlight_symbol("› ");
    let mut state = ListState::default();
    if !items.is_empty() {
        *selected = (*selected).min(items.len() - 1);
        state.select(Some(*selected));
    }
    frame.render_stateful_widget(list, layout[2], &mut state);
    frame.render_widget(
        Paragraph::new("↑/↓ or j/k move  ·  Enter select  ·  Esc back  ·  number shortcut")
            .style(Style::default().fg(Color::DarkGray)),
        layout[3],
    );
}

fn too_small(area: Rect) -> bool {
    area.width < 20 || area.height < 6
}

fn move_selection(selected: &mut usize, item_count: usize, down: bool) {
    if item_count == 0 {
        *selected = 0;
    } else if down {
        *selected = selected.saturating_add(1).min(item_count - 1);
    } else {
        *selected = selected.saturating_sub(1);
    }
}

struct RawMode;
impl RawMode {
    fn enable() -> io::Result<Self> {
        enable_raw_mode()?;
        Ok(Self)
    }
}
impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

#[cfg(test)]
pub(super) fn render_to_test_backend(
    width: u16,
    height: u16,
    title: &str,
    lines: &[Line<'static>],
) -> Vec<String> {
    use ratatui::backend::TestBackend;
    let backend = TestBackend::new(width, height);
    let mut term = Terminal::new(backend).expect("test backend");
    let _ = term.draw(|frame| {
        if too_small(frame.area()) {
            frame.render_widget(
                Paragraph::new("Terminal too small. Resize to at least 20 x 6."),
                frame.area(),
            );
            return;
        }
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1)])
            .split(frame.area());
        frame.render_widget(Paragraph::new(title), layout[0]);
        frame.render_widget(
            Paragraph::new(lines.to_vec())
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL)),
            layout[1],
        );
    });
    term.backend()
        .buffer()
        .content()
        .chunks(width as usize)
        .map(|row| {
            row.iter()
                .map(|cell| cell.symbol())
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{content_layout, move_selection, render_menu};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Rect;

    #[test]
    fn menu_navigation_clamps_at_both_ends() {
        let mut selected = 0;
        move_selection(&mut selected, 3, false);
        assert_eq!(selected, 0);
        move_selection(&mut selected, 3, true);
        move_selection(&mut selected, 3, true);
        move_selection(&mut selected, 3, true);
        assert_eq!(selected, 2);
        move_selection(&mut selected, 0, false);
        assert_eq!(selected, 0);
    }

    #[test]
    fn menu_uses_native_list_and_clamps_selection_in_small_viewport() {
        let backend = TestBackend::new(40, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        let items = [
            ("1", "Investigate", "Inspect one local file"),
            ("0", "Back", "Return"),
        ];
        let mut selected = usize::MAX;
        terminal
            .draw(|frame| {
                render_menu(
                    frame,
                    "CyberFeed",
                    "Local investigation",
                    &items,
                    &mut selected,
                )
            })
            .unwrap();
        assert_eq!(selected, 1);
        let buffer = terminal.backend().buffer();
        let text = buffer
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("Back"));
    }

    #[test]
    fn prompt_slot_and_centered_content_fit_representative_sizes() {
        for (width, height) in [(40, 12), (80, 24), (120, 40)] {
            let (_, body, prompt) = content_layout(Rect::new(0, 0, width, height), true);
            let prompt = prompt.unwrap();
            assert_eq!(prompt.y + prompt.height, height);
            assert_eq!(body.y + body.height, prompt.y);
            assert!(body.width <= super::super::INNER_WIDTH as u16 + 2);
            assert!(body.width <= width);
        }
    }
}
