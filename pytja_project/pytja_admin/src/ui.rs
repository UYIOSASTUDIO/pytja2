use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs, Row, Table, Cell, Clear},
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
        CurrentTab::Databases => draw_databases(f, app, chunks[1]), // NEU
    }

    // --- POPUP LAYER ---

    // 1. User Action Menu
    if app.active_popup == crate::app::PopupType::UserActions {
        draw_user_popup(f, app);
    }

    // 2. Input Field (z.B. für Role Change)
    if app.active_popup == crate::app::PopupType::ChangeRoleInput {
        draw_input_popup(f, app, "Enter new Role Name:");
    }

    let status = Paragraph::new(format!("Status: {}", app.status_message))
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(status, chunks[2]);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = vec!["Dashboard [1]", "Sessions [2]", "Roles [3]", "Databases [4]"]
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
        Line::from(vec![Span::styled("PYTJA COMMAND CENTER V3.0", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))]),
        Line::from(""),
        Line::from(format!("Active Sessions: {}", app.total_active)),
        Line::from(format!("Defined Roles:   {}", app.roles.len())),
        Line::from(format!("Mounted DBs:     {}", app.mounts.len())),
        Line::from(""),
        Line::from(vec![Span::styled("CONTROLS:", Style::default().add_modifier(Modifier::UNDERLINED))]),
        Line::from("  [1-4] Switch Tabs"),
        Line::from("  [r]   Refresh Data"),
        Line::from("  [q]   Quit"),
    ];
    let p = Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("Overview"));
    f.render_widget(p, area);
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
            Cell::from(s.role.clone()),
            Cell::from(s.last_activity.clone()),
        ]).style(style)
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(10), Constraint::Length(15), Constraint::Length(15),
        Constraint::Length(10), Constraint::Min(20)
    ])
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Active Sessions (Enter to manage)"));

    f.render_widget(table, area);
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

// NEU: Database Tab
fn draw_databases(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["Name", "Type", "Status"])
        .style(Style::default().fg(Color::Yellow));

    let rows: Vec<Row> = app.mounts.iter().map(|m| {
        Row::new(vec![
            Cell::from(m.name.clone()),
            // FIX: 'type' ist Keyword, daher r#type nutzen (Prost generiert das so)
            Cell::from(m.r#type.clone()),
            if m.is_connected {
                Cell::from("CONNECTED").style(Style::default().fg(Color::Green))
            } else {
                Cell::from("ERROR").style(Style::default().fg(Color::Red))
            },
        ])
    }).collect();

    let table = Table::new(rows, [Constraint::Percentage(30), Constraint::Percentage(30), Constraint::Percentage(40)])
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Connected Databases"));
    f.render_widget(table, area);
}

fn draw_user_popup(f: &mut Frame, app: &App) {
    let block = Block::default().title("User Actions").borders(Borders::ALL).style(Style::default().bg(Color::DarkGray));
    let area = centered_rect(60, 25, f.size());

    if app.sessions.is_empty() { return; }
    let session = &app.sessions[app.selected_session_index];

    let text = vec![
        Line::from(format!("User: {}", session.username).yellow().bold()),
        Line::from(format!("Role: {}", session.role)),
        Line::from(""),
        Line::from("[R] Change Role (Set Admin/Editor...)"),
        Line::from("[K] Kick Session (Force Logout)"),
        Line::from("[B] Ban User (Deactivate Account)"),
        Line::from(""),
        Line::from("[Esc] Cancel"),
    ];

    let p = Paragraph::new(text).block(block).alignment(ratatui::layout::Alignment::Center);
    f.render_widget(Clear, area);
    f.render_widget(p, area);
}

// NEU: Generisches Input Popup
fn draw_input_popup(f: &mut Frame, app: &App, title: &str) {
    let block = Block::default().title(title).borders(Borders::ALL).style(Style::default().bg(Color::Blue));
    let area = centered_rect(50, 10, f.size()); // Kleines Fenster

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(app.input_buffer.clone(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD))),
    ];

    let p = Paragraph::new(text).block(block).alignment(ratatui::layout::Alignment::Center);
    f.render_widget(Clear, area);
    f.render_widget(p, area);
}

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