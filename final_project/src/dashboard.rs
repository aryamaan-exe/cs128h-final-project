use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    text::Line,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::stats::Stats;

pub fn run_dashboard(stats: Arc<Mutex<Stats>>) -> Result<(), Box<dyn std::error::Error>> {
    // --- Terminal setup ---

    // Raw mode stops the terminal from buffering keystrokes until Enter.
    // Without it we wouldn't be able to detect 'q' immediately.
    enable_raw_mode()?;

    let mut stdout = io::stdout();

    // EnterAlternateScreen switches to a blank overlay buffer. When we exit,
    // LeaveAlternateScreen restores whatever was in the terminal before we ran.
    execute!(stdout, EnterAlternateScreen)?;

    // CrosstermBackend tells ratatui how to actually draw to the terminal.
    // Terminal wraps it and manages the frame-by-frame rendering.
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // --- Main render loop ---
    loop {
        // terminal.draw() gives us a `Frame` and calls our closure.
        // Everything inside the closure is one rendered frame.
        terminal.draw(|frame| {
            // Snapshot the stats — lock the mutex, copy what we need, then
            // release the lock before doing any rendering work.
            let s = stats.lock().unwrap();
            let total = s.total;
            let tcp   = s.tcp;
            let udp   = s.udp;
            let arp   = s.arp;
            let other = s.other;

            // Sort senders by packet count (highest first), keep top 10.
            // We collect references into a Vec so we can sort them.
            let mut sender_list: Vec<(&String, &usize)> = s.senders.iter().collect();
            sender_list.sort_by(|a, b| b.1.cmp(a.1));
            let top_senders: Vec<String> = sender_list
                .iter()
                .take(10)
                .map(|(ip, count)| format!("{:<20} {:>6} pkts", ip, count))
                .collect();

            drop(s); // explicitly release the Mutex lock before we start drawing

            // --- Layout ---
            // Split the whole screen vertically into 4 rows.
            // Constraint::Length(n) = exactly n rows tall
            // Constraint::Min(0)    = take up all remaining space
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),  // title bar
                    Constraint::Length(9),  // protocol stats
                    Constraint::Min(0),     // top senders (fills the rest)
                    Constraint::Length(1),  // footer hint
                ])
                .split(frame.area());

            // --- Title bar ---
            let title = Paragraph::new("  Packet Capture Dashboard  —  live")
                .block(Block::default().borders(Borders::ALL));
            frame.render_widget(title, rows[0]);

            // --- Stats panel ---
            // Paragraph::new() accepts a Vec<Line>, where each Line is one row of text.
            let stats_lines = vec![
                Line::from(format!("  Total received : {}", total)),
                Line::from(format!("  TCP            : {}", tcp)),
                Line::from(format!("  UDP            : {}", udp)),
                Line::from(format!("  ARP            : {}", arp)),
                Line::from(format!("  Other          : {}", other)),
            ];
            let stats_widget = Paragraph::new(stats_lines)
                .block(Block::default().borders(Borders::ALL).title(" Protocol Breakdown "));
            frame.render_widget(stats_widget, rows[1]);

            // --- Top senders panel ---
            // List::new() takes an iterator of ListItem, one per row.
            let items: Vec<ListItem> = top_senders
                .iter()
                .map(|line| ListItem::new(format!("  {}", line)))
                .collect();
            let senders_widget = List::new(items)
                .block(Block::default().borders(Borders::ALL).title(" Top Senders (IP / packets) "));
            frame.render_widget(senders_widget, rows[2]);

            // --- Footer ---
            let footer = Paragraph::new("  Press q to quit");
            frame.render_widget(footer, rows[3]);
        })?;

        // Poll for a keypress for up to 200 ms, then loop and redraw.
        // This gives us ~5 redraws per second without busy-waiting.
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    // --- Cleanup ---
    // Always restore the terminal, even on quit. If we skip this the user's
    // shell will be left in raw mode (no echo, broken input) until they restart it.
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

    Ok(())
}
