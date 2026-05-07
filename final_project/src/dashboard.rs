use std::sync::mpsc;

use egui::{Color32, RichText, ScrollArea};
use egui_plot::{Bar, BarChart, Line, Plot, PlotPoints};

use crate::analytics::{Analytics, PacketInfo, Protocol};
use crate::cli::Args;

pub fn run(args: Args) {
    let (tx, rx) = mpsc::channel::<PacketInfo>();
    let args_for_thread = args.clone();

    std::thread::spawn(move || {
        if let Err(e) = crate::capture::start_capture(args_for_thread, Some(tx)) {
            eprintln!("Capture error: {}", e);
        }
    });

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("rustsniff")
            .with_inner_size([1200.0, 800.0]),
        ..Default::default()
    };

    eframe::run_native(
        "rustsniff",
        options,
        Box::new(|cc| {
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill       = Color32::BLACK;
            visuals.window_fill      = Color32::BLACK;
            visuals.extreme_bg_color = Color32::from_gray(6);
            visuals.faint_bg_color   = Color32::from_gray(10);
            cc.egui_ctx.set_visuals(visuals);
            Ok(Box::new(DashboardApp::new(rx)))
        }),
    )
    .unwrap();
}

#[derive(PartialEq)]
enum Tab { LiveFeed, Metrics }

pub struct DashboardApp {
    rx:          mpsc::Receiver<PacketInfo>,
    analytics:   Analytics,
    active_tab:  Tab,
    auto_scroll: bool,
}

impl DashboardApp {
    pub fn new(rx: mpsc::Receiver<PacketInfo>) -> Self {
        DashboardApp { rx, analytics: Analytics::new(), active_tab: Tab::LiveFeed, auto_scroll: true }
    }
}

impl eframe::App for DashboardApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(info) = self.rx.try_recv() {
            self.analytics.add_packet(info);
        }
        self.analytics.tick_time_series();

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, Tab::LiveFeed, "live feed");
                ui.selectable_value(&mut self.active_tab, Tab::Metrics,  "metrics");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.active_tab {
                Tab::LiveFeed => show_live_feed(ui, &self.analytics, &mut self.auto_scroll),
                Tab::Metrics  => show_metrics(ui, &self.analytics),
            }
        });

        ctx.request_repaint();
    }
}

fn show_live_feed(ui: &mut egui::Ui, analytics: &Analytics, auto_scroll: &mut bool) {
    ui.horizontal(|ui| {
        ui.checkbox(auto_scroll, "auto-scroll");
        ui.weak(format!("{} packets", analytics.feed.len()));
    });

    let row_height = ui.text_style_height(&egui::TextStyle::Body);

    ScrollArea::vertical()
        .stick_to_bottom(*auto_scroll)
        .show_rows(ui, row_height, analytics.feed.len(), |ui, range| {
            for idx in range {
                let info = &analytics.feed[idx];
                let (proto_str, color) = match info.protocol {
                    Protocol::Tcp   => ("TCP",   Color32::from_rgb(80, 200, 80)),
                    Protocol::Udp   => ("UDP",   Color32::from_rgb(80, 160, 255)),
                    Protocol::Arp   => ("ARP",   Color32::from_rgb(220, 200, 60)),
                    Protocol::Other => ("OTHER", Color32::from_rgb(220, 80, 80)),
                };
                ui.horizontal(|ui| {
                    ui.monospace(RichText::new(format!("[{}]", info.time_str)).weak());
                    ui.colored_label(color, format!("{:<5}", proto_str));
                    ui.monospace(format!("{:<25}", info.src));
                    ui.monospace("→");
                    ui.monospace(format!("{:<25}", info.dst));
                    ui.weak(format!("#{}", info.number));
                });
            }
        });
}

fn show_metrics(ui: &mut egui::Ui, analytics: &Analytics) {
    ui.columns(2, |cols| {
        let pps_data: Vec<[f64; 2]> = analytics.time_series.iter()
            .enumerate().map(|(i, b)| [i as f64, b[0]]).collect();
        cols[0].weak("packets / sec");
        Plot::new("pps_plot")
            .height(140.0)
            .show_x(false).show_y(false)
            .show(&mut cols[0], |p| {
                p.line(Line::new(PlotPoints::new(pps_data)).color(Color32::from_rgb(100, 220, 100)));
            });

        let bps_data: Vec<[f64; 2]> = analytics.time_series.iter()
            .enumerate().map(|(i, b)| [i as f64, b[1]]).collect();
        cols[1].weak("bytes / sec");
        Plot::new("bps_plot")
            .height(140.0)
            .show_x(false).show_y(false)
            .show(&mut cols[1], |p| {
                p.line(Line::new(PlotPoints::new(bps_data)).color(Color32::from_rgb(100, 180, 255)));
            });
    });

    ui.add_space(8.0);

    let bars = vec![
        Bar::new(0.0, analytics.tcp_count   as f64).name("TCP")  .fill(Color32::from_rgb(80, 200, 80)),
        Bar::new(1.0, analytics.udp_count   as f64).name("UDP")  .fill(Color32::from_rgb(80, 160, 255)),
        Bar::new(2.0, analytics.arp_count   as f64).name("ARP")  .fill(Color32::from_rgb(220, 200, 60)),
        Bar::new(3.0, analytics.other_count as f64).name("Other").fill(Color32::from_rgb(220, 80, 80)),
    ];
    ui.weak("protocol breakdown");
    Plot::new("proto_chart")
        .height(140.0)
        .show_x(false).show_y(false)
        .show(ui, |p| { p.bar_chart(BarChart::new(bars)); });
    ui.horizontal(|ui| {
        ui.colored_label(Color32::from_rgb(80, 200, 80),  "TCP");
        ui.colored_label(Color32::from_rgb(80, 160, 255), "UDP");
        ui.colored_label(Color32::from_rgb(220, 200, 60), "ARP");
        ui.colored_label(Color32::from_rgb(220, 80, 80),  "Other");
    });

    ui.add_space(8.0);
    ui.weak("top talkers");

    let mut sorted: Vec<(&String, &(u64, u64))> = analytics.top_talkers.iter().collect();
    sorted.sort_by(|a, b| b.1.0.cmp(&a.1.0));
    sorted.truncate(20);

    egui::Grid::new("top_talkers")
        .striped(true)
        .num_columns(3)
        .min_col_width(160.0)
        .show(ui, |ui| {
            ui.weak("source ip");
            ui.weak("packets");
            ui.weak("bytes");
            ui.end_row();
            for (ip, (pkts, bytes)) in &sorted {
                ui.monospace(ip.as_str());
                ui.monospace(pkts.to_string());
                let b = *bytes;
                let size_str = if b < 1024 {
                    format!("{} B", b)
                } else if b < 1024 * 1024 {
                    format!("{:.1} KB", b as f64 / 1024.0)
                } else {
                    format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
                };
                ui.monospace(size_str);
                ui.end_row();
            }
        });
}

