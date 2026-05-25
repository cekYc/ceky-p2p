//! Ratatui UI drawing logic.

use crate::app::TuiApp;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Sparkline},
    Frame,
};
use std::sync::atomic::Ordering;

pub fn draw(f: &mut Frame, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(7),   // Top: Network & Traffic
                Constraint::Length(5),   // Middle: DHT & SuperNode
                Constraint::Min(10),     // Bottom: Logs & Transfers
            ]
            .as_ref(),
        )
        .split(f.area());

    draw_top_network(f, app, chunks[0]);
    draw_middle_dht(f, app, chunks[1]);
    draw_bottom_transfers_logs(f, app, chunks[2]);
}

fn draw_top_network(f: &mut Frame, app: &TuiApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(35), Constraint::Percentage(35)].as_ref())
        .split(area);

    // Left: Connections
    let tcp = app.metrics.active_tcp_connections.load(Ordering::Relaxed);
    let conn_text = vec![
        Line::from(vec![Span::raw(format!("Active TCP: {}", tcp))]),
        Line::from(vec![Span::raw(format!("Active UDP: {}", 0))]), // Dummy for now
    ];
    let conn_block = Paragraph::new(conn_text)
        .block(Block::default().title("Connections").borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(conn_block, chunks[0]);

    // Middle: TX Sparkline
    let tx_rate = app.metrics.tx_rate.load(Ordering::Relaxed);
    let tx_title = format!("TX Rate: {} B/s", tx_rate);
    let tx_sparkline = Sparkline::default()
        .block(Block::default().title(tx_title).borders(Borders::ALL))
        .data(&app.tx_history)
        .style(Style::default().fg(Color::Green));
    f.render_widget(tx_sparkline, chunks[1]);

    // Right: RX Sparkline
    let rx_rate = app.metrics.rx_rate.load(Ordering::Relaxed);
    let rx_title = format!("RX Rate: {} B/s", rx_rate);
    let rx_sparkline = Sparkline::default()
        .block(Block::default().title(rx_title).borders(Borders::ALL))
        .data(&app.rx_history)
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(rx_sparkline, chunks[2]);
}

fn draw_middle_dht(f: &mut Frame, app: &TuiApp, area: Rect) {
    let dht_active = app.metrics.dht_active_peers.load(Ordering::Relaxed);
    let dht_total = app.metrics.dht_total_peers.load(Ordering::Relaxed);

    let text = vec![
        Line::from(format!("Routing Table: {} active / {} total peers", dht_active, dht_total)),
        Line::from("SuperNode Status: Not Promoted"), // Placeholder for SuperNode state
    ];
    let p = Paragraph::new(text)
        .block(Block::default().title("Kademlia DHT Topolojisi").borders(Borders::ALL))
        .style(Style::default().fg(Color::Magenta));
    f.render_widget(p, area);
}

fn draw_bottom_transfers_logs(f: &mut Frame, app: &TuiApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area);

    // Left: Transfers
    let transfers = app.metrics.transfers.read().unwrap();
    let mut transfer_list = Vec::new();
    for t in transfers.iter() {
        let percent = if t.total_chunks == 0 { 0 } else { (t.completed_chunks * 100) / t.total_chunks };
        let dir = if t.is_sending { "Tx" } else { "Rx" };
        let s = format!("[{}] {} - {}% ({}/{})", dir, t.file_name, percent, t.completed_chunks, t.total_chunks);
        transfer_list.push(ListItem::new(s));
    }
    let transfer_block = List::new(transfer_list)
        .block(Block::default().title("Active Transfers").borders(Borders::ALL))
        .style(Style::default().fg(Color::LightBlue));
    f.render_widget(transfer_block, chunks[0]);

    // Right: Logs
    let logs: Vec<ListItem> = app
        .logs
        .iter()
        .rev() // Show newest first
        .take(area.height as usize - 2) // Fit in box
        .map(|l| {
            let color = match l.level.as_str() {
                "ERROR" => Color::Red,
                "WARN" => Color::Yellow,
                "INFO" => Color::White,
                "DEBUG" => Color::DarkGray,
                _ => Color::White,
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", l.timestamp), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("[{}] ", l.level), Style::default().fg(color)),
                Span::raw(l.message.clone()),
            ]))
        })
        .collect();

    let logs_block = List::new(logs)
        .block(Block::default().title("Event Logs").borders(Borders::ALL));
    f.render_widget(logs_block, chunks[1]);
}
