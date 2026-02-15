use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs, Row, Table, Cell, Clear, TableState},
    Frame,
};
use crate::app::{App, CurrentTab};

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Header/Tabs
            Constraint::Min(0),    // Content
            Constraint::Length(1), // Footer
        ].as_ref())
        .split(f.size());

    draw_tabs(f, app, chunks[0]);

    match app.current_tab {
        CurrentTab::Dashboard => draw_dashboard(f, app, chunks[1]),
        CurrentTab::Sessions => draw_sessions(f, app, chunks[1]),
        CurrentTab::Roles => draw_roles(f, app, chunks[1]),
    }

    if app.active_popup == crate::app::PopupType::UserActions {
        draw_user_popup(f, app);
    }

    let status = Paragraph::new(format!("Status: {}", app.status_message))
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(status, chunks[2]);
}

fn draw_sessions(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["ID", "User", "IP", "Role", "Last Active"])
        .style(Style::default().fg(Color::Yellow));

    let rows: Vec<Row> = app.sessions.iter().enumerate().map(|(i, s)| {
        let style = if i == app.selected_session_index {
            Style::default().bg(Color::Blue).fg(Color::White)
        } else {
            Style::default()
        };

        Row::new(vec![
            Cell::from(s.session_id.chars().take(8).collect::<String>()),
            Cell::from(s.username.clone()),
            Cell::from(s.ip_address.clone()),
            Cell::from(s.role.clone()), // FIX: Echte Rolle anzeigen!
            Cell::from(s.last_activity.clone()),
        ]).style(style)
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(10), Constraint::Length(15), Constraint::Length(15),
        Constraint::Length(10), Constraint::Min(20)
    ])
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Active Sessions (Up/Down to select, Enter to act)"));

    f.render_widget(table, area);
}

// Das Popup Widget
fn draw_user_popup(f: &mut Frame, app: &App) {
    let block = Block::default().title("User Actions").borders(Borders::ALL).style(Style::default().bg(Color::DarkGray));
    let area = centered_rect(60, 20, f.size());

    let session = &app.sessions[app.selected_session_index];
    let text = vec![
        Line::from(format!("Selected User: {}", session.username).yellow().bold()),
        Line::from(""),
        Line::from("[K] Kick Session"),
        Line::from("[B] Ban User (Kick & Lock)"),
        Line::from(""),
        Line::from("[Esc] Cancel"),
    ];

    let p = Paragraph::new(text).block(block).alignment(ratatui::layout::Alignment::Center);

    f.render_widget(Clear, area); // Hintergrund löschen
    f.render_widget(p, area);
}

// Helper für Zentrierung
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ].as_ref())
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ].as_ref())
        .split(popup_layout[1])[1]
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    // FIX: Explizite Typ-Annotation für den Compiler
    let titles: Vec<Line> = vec!["Dashboard [1]", "Sessions [2]", "Roles [3]"]
        .iter()
        .map(|t| Line::from(Span::styled(*t, Style::default().fg(Color::Green))))
        .collect();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title("Pytja Admin Console V3.0"))
        .select(app.current_tab as usize)
        .highlight_style(Style::default().add_modifier(Modifier::BOLD).bg(Color::DarkGray));

    f.render_widget(tabs, area);
}

fn draw_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let text = vec![
        Line::from(""),
        Line::from(vec![Span::styled("PYTJA ENTERPRISE HUB", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))]),
        Line::from(""),
        Line::from(format!("Active Sessions: {}", app.total_active)),
        Line::from(format!("Defined Roles:   {}", app.roles.len())),
        Line::from(""),
        Line::from("Press 'r' to refresh data."),
        Line::from("Press 'q' to quit."),
    ];
    let p = Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("Overview"));
    f.render_widget(p, area);
}

fn draw_roles(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app.roles.iter().map(|r| {
        let perms = r.permissions.join(", ");
        ListItem::new(format!("{} -> [{}]", r.name.to_uppercase(), perms))
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("RBAC Roles"))
        .highlight_style(Style::default().bg(Color::Blue));
    f.render_widget(list, area);
}