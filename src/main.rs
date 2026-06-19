#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod anticheat;
mod asm_x86;
mod assembler;
mod inject;
mod memory;
mod pointer;
mod process;
mod proxy;
mod scan;
mod value;

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pointer::{ModuleRanges, PtrPath, PtrScanParams};

use eframe::egui;

use process::{OpenProcessHandle, ProcessInfo};
use scan::{Match, ScanKind, ScanProgress, Scanner};
use value::ValueType;

/// Uma busca em andamento numa thread de fundo.
struct ScanTask {
    progress: Arc<ScanProgress>,
    rx: Receiver<Vec<Match>>,
    is_next: bool,
}

/// Um pointer scan em andamento numa thread de fundo.
struct PtrTask {
    progress: Arc<ScanProgress>,
    rx: Receiver<Vec<PtrPath>>,
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1000.0, 680.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Quarry",
        options,
        Box::new(|_cc| Ok(Box::<App>::default())),
    )
}

/// Uma entrada salva na "cheat table".
struct SavedEntry {
    address: u64,
    value_type: ValueType,
    desc: String,
    frozen: bool,
    edit_text: String,
    /// se presente, o endereco e resolvido dinamicamente por esta cadeia.
    pointer: Option<PtrPath>,
    /// numero de bytes a ler para tipos string (0 para tipos numericos).
    str_len: usize,
}

impl SavedEntry {
    /// Quantos bytes ler/escrever para exibir o valor desta entrada.
    fn read_len(&self) -> usize {
        if self.value_type.is_string() {
            self.str_len
        } else {
            self.value_type.size()
        }
    }
}

/// Alvos congelados compartilhados com a thread de freeze.
type FrozenTargets = Arc<Mutex<Vec<(u64, Vec<u8>)>>>;

/// As duas grandes secoes de exploracao do Quarry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    /// Metodos safe que NAO tocam o processo — uso com AC kernel (Vanguard...).
    Kernel,
    /// Acesso direto ao processo (scan/patch/injecao) — sem AC kernel.
    General,
}

/// Sub-visões da aba Proxy (espelham o Burp: histórico, intercept, repeater).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProxyView {
    History,
    Intercept,
    Repeater,
    Rules,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    // --- General Exploring (acessa o processo) ---
    Busca,
    Pointer,
    Assembler,
    Injecao,
    // --- Kernel Exploring (safe, sem injecao) ---
    Proxy,
    KernelOverview,
}

impl Tab {
    fn section(self) -> Section {
        match self {
            Tab::Busca | Tab::Pointer | Tab::Assembler | Tab::Injecao => Section::General,
            Tab::Proxy | Tab::KernelOverview => Section::Kernel,
        }
    }
}

const AA_TEMPLATE: &str = "\
[ENABLE]
// 1) ache a instrucao no modulo do jogo (use ?? como curinga)
// aobscanmodule(inject, jogo.exe, 89 83 A4 00 00 00)
// 2) aloque um code cave perto do alvo (saltos rel32 alcancam)
// alloc(newmem, 0x1000, inject)
// registersymbol(inject)
//
// newmem:
//   mov [rbx+0x000000A4], 999   // forca o valor (ou escreva o efeito desejado)
//   jmp return
//
// inject:
//   jmp newmem
//   nop                         // complete o tamanho da instrucao original
// return:

[DISABLE]
// inject:
//   db 89 83 A4 00 00 00        // restaura os bytes originais
// unregistersymbol(inject)
// dealloc(newmem)
";

struct App {
    processes: Vec<ProcessInfo>,
    proc_filter: String,
    show_process_picker: bool,

    attached: Option<Arc<OpenProcessHandle>>,
    attached_name: String,

    value_type: ValueType,
    scan_kind: ScanKind,
    value_text: String,
    fast_scan: bool,

    scanner: Scanner,
    scan_task: Option<ScanTask>,
    status: String,

    saved: Vec<SavedEntry>,
    frozen_targets: FrozenTargets,

    // bases dos modulos no processo (nome -> base), p/ resolver ponteiros
    module_bases: HashMap<String, u64>,

    // --- aba pointer scan ---
    ptr_target_text: String,
    ptr_max_offset_text: String,
    ptr_depth_text: String,
    ptr_align_text: String,
    ptr_results: Vec<PtrPath>,
    ptr_task: Option<PtrTask>,

    // --- aba auto assembler ---
    aa_script: String,
    aa_state: assembler::AsmState,
    aa_log: Vec<String>,

    // --- secoes / classificacao de anticheat ---
    section: Section,
    tab: Tab,
    /// classificacao do alvo (None = nada anexado ainda).
    detection: Option<anticheat::Detection>,

    // --- proxy HTTPS (Kernel Exploring) ---
    proxy: Option<proxy::ProxyHandle>,
    proxy_port_text: String,
    proxy_view: ProxyView,
    proxy_filter: String,
    proxy_selected: Option<u64>,
    // intercept: buffers do item em edição
    icpt_id: Option<u64>,
    icpt_headers: String,
    icpt_body: String,
    icpt_follow: bool,
    // repeater
    rep_method: String,
    rep_url: String,
    rep_headers: String,
    rep_body: String,
    rep_rx: Option<proxy::RepeaterRx>,
    rep_busy: bool,
    rep_status: u16,
    rep_resp_headers: String,
    rep_resp_body: String,
    // match & replace
    rules: Vec<proxy::Rule>,

    // --- aba de injecao ---
    modules: Vec<inject::ModuleInfo>,
    module_filter: String,
    aob_text: String,
    aob_results: Vec<u64>,
    dll_path: String,
    patch_addr_text: String,
    patch_bytes_text: String,
    nop_addr_text: String,
    nop_len_text: String,
}

impl Default for App {
    fn default() -> Self {
        let frozen_targets: FrozenTargets = Arc::new(Mutex::new(Vec::new()));
        Self {
            processes: Vec::new(),
            proc_filter: String::new(),
            show_process_picker: false,
            attached: None,
            attached_name: String::new(),
            value_type: ValueType::I32,
            scan_kind: ScanKind::Exact,
            value_text: String::new(),
            fast_scan: true,
            scanner: Scanner::new(ValueType::I32),
            scan_task: None,
            status: "Nenhum processo anexado.".into(),
            saved: Vec::new(),
            frozen_targets,
            module_bases: HashMap::new(),
            ptr_target_text: String::new(),
            ptr_max_offset_text: "2048".into(),
            ptr_depth_text: "4".into(),
            ptr_align_text: "4".into(),
            ptr_results: Vec::new(),
            ptr_task: None,
            aa_script: AA_TEMPLATE.to_string(),
            aa_state: assembler::AsmState::new(),
            aa_log: Vec::new(),
            section: Section::General,
            tab: Tab::Busca,
            detection: None,
            proxy: None,
            proxy_port_text: "8080".into(),
            proxy_view: ProxyView::History,
            proxy_filter: String::new(),
            proxy_selected: None,
            icpt_id: None,
            icpt_headers: String::new(),
            icpt_body: String::new(),
            icpt_follow: false,
            rep_method: "GET".into(),
            rep_url: String::new(),
            rep_headers: String::new(),
            rep_body: String::new(),
            rep_rx: None,
            rep_busy: false,
            rep_status: 0,
            rep_resp_headers: String::new(),
            rep_resp_body: String::new(),
            rules: Vec::new(),
            modules: Vec::new(),
            module_filter: String::new(),
            aob_text: String::new(),
            aob_results: Vec::new(),
            dll_path: String::new(),
            patch_addr_text: String::new(),
            patch_bytes_text: String::new(),
            nop_addr_text: String::new(),
            nop_len_text: "1".into(),
        }
    }
}

fn parse_addr(text: &str) -> Option<u64> {
    let t = text.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).ok()
}

impl App {
    fn attach(&mut self, pid: u32, name: String) {
        match OpenProcessHandle::open(pid) {
            Ok(h) => {
                let handle = Arc::new(h);
                self.spawn_freezer(handle.clone());
                self.attached = Some(handle);
                self.attached_name = format!("{name} (pid {pid})");
                self.scanner.reset();
                self.refresh_module_bases(pid);
                self.classify(pid, &name);
                self.status = format!("Anexado em {name}.");
            }
            Err(e) => {
                self.status = format!(
                    "Falha ao anexar (pid {pid}): {e}. Rode o Quarry como Administrador."
                );
            }
        }
    }

    /// Classifica o alvo (AC kernel / user-mode / sem protecao) e roteia
    /// para a secao correta. Com AC kernel, forca a secao Kernel Exploring.
    fn classify(&mut self, pid: u32, exe_name: &str) {
        let modules = inject::list_modules(pid);
        let det = anticheat::detect(exe_name, &modules);
        if det.protection.blocks_injection() {
            // alvo protegido por AC kernel: empurra para a aba safe.
            self.section = Section::Kernel;
            self.tab = Tab::KernelOverview;
        } else {
            self.section = Section::General;
            self.tab = Tab::Busca;
        }
        self.detection = Some(det);
    }

    /// True quando a injecao/patch deve ficar bloqueada (AC kernel detectado).
    fn injection_blocked(&self) -> bool {
        self.detection
            .as_ref()
            .is_some_and(|d| d.protection.blocks_injection())
    }

    /// Recolhe a resposta do Repeater quando pronta (sem bloquear).
    fn poll_repeater(&mut self) {
        let Some(rx) = &mut self.rep_rx else {
            return;
        };
        match proxy::poll_repeater(rx) {
            proxy::RepeaterPoll::Pending => {}
            proxy::RepeaterPoll::Done(r) => {
                self.rep_status = r.status;
                self.rep_resp_headers = r.headers;
                self.rep_resp_body = r.body;
                self.rep_busy = false;
                self.rep_rx = None;
            }
            proxy::RepeaterPoll::Closed => {
                self.rep_busy = false;
                self.rep_rx = None;
            }
        }
    }

    /// Thread que reescreve os valores congelados periodicamente.
    fn spawn_freezer(&self, handle: Arc<OpenProcessHandle>) {
        let targets = self.frozen_targets.clone();
        std::thread::spawn(move || loop {
            {
                let list = targets.lock().unwrap();
                for (addr, bytes) in list.iter() {
                    memory::write_bytes(handle.raw(), *addr, bytes);
                }
            }
            std::thread::sleep(Duration::from_millis(40));
        });
    }

    fn rebuild_frozen_targets(&self) {
        let mut list = self.frozen_targets.lock().unwrap();
        list.clear();
        if let Some(h) = &self.attached {
            for e in self.saved.iter().filter(|e| e.frozen) {
                let Some(addr) = self.entry_address(e) else {
                    continue;
                };
                if let Some(bytes) = e.value_type.parse_to_bytes(&e.edit_text) {
                    list.push((addr, bytes));
                } else if let Some(cur) =
                    memory::read_bytes(h.raw(), addr, e.value_type.size())
                {
                    list.push((addr, cur));
                }
            }
        }
    }

    /// Le e valida o valor digitado; retorna None se invalido p/ o tipo.
    fn parse_target(&self) -> Option<f64> {
        self.value_type
            .parse_to_bytes(&self.value_text)
            .and_then(|b| self.value_type.read_f64(&b))
    }

    fn do_first_scan(&mut self) {
        if self.scan_task.is_some() {
            return;
        }
        let Some(h) = self.attached.clone() else {
            self.status = "Anexe um processo primeiro.".into();
            return;
        };

        if self.value_type.is_string() {
            self.start_string_scan(h, false);
            return;
        }

        let target = self.parse_target();
        if self.scan_kind.needs_value() && target.is_none() {
            self.status = "Valor invalido para o tipo selecionado.".into();
            return;
        }
        self.scanner = Scanner::new(self.value_type);
        self.scanner.fast_scan = self.fast_scan;

        let regions = memory::enumerate_regions(h.raw());
        let progress = ScanProgress::new(regions.len());
        let (tx, rx) = std::sync::mpsc::channel();

        let value_type = self.value_type;
        let fast_scan = self.fast_scan;
        let kind = self.scan_kind;
        let target = target.unwrap_or(0.0);
        let prog = progress.clone();
        std::thread::spawn(move || {
            let result = scan::first_scan_job(
                h.raw(),
                &regions,
                value_type,
                fast_scan,
                kind,
                target,
                &prog,
            );
            let _ = tx.send(result);
        });

        self.scan_task = Some(ScanTask {
            progress,
            rx,
            is_next: false,
        });
        self.status = "First scan em andamento...".into();
    }

    /// Dispara um scan de string (first ou next) numa thread de fundo.
    fn start_string_scan(&mut self, h: Arc<OpenProcessHandle>, is_next: bool) {
        let Some(pattern) = self.value_type.parse_to_bytes(&self.value_text) else {
            self.status = "Texto invalido.".into();
            return;
        };
        if pattern.is_empty() {
            self.status = "Digite um texto para procurar.".into();
            return;
        }

        let (tx, rx) = std::sync::mpsc::channel();
        if is_next {
            let current = std::mem::take(&mut self.scanner.matches);
            let progress = ScanProgress::new(current.len());
            let prog = progress.clone();
            std::thread::spawn(move || {
                let result = scan::next_scan_string_job(h.raw(), current, &pattern, &prog);
                let _ = tx.send(result);
            });
            self.scan_task = Some(ScanTask { progress, rx, is_next: true });
            self.status = "Next scan (texto) em andamento...".into();
        } else {
            self.scanner = Scanner::new(self.value_type);
            let regions = memory::enumerate_regions(h.raw());
            let progress = ScanProgress::new(regions.len());
            let prog = progress.clone();
            std::thread::spawn(move || {
                let result = scan::first_scan_string_job(h.raw(), &regions, &pattern, &prog);
                let _ = tx.send(result);
            });
            self.scan_task = Some(ScanTask { progress, rx, is_next: false });
            self.status = "First scan (texto) em andamento...".into();
        }
    }

    fn do_next_scan(&mut self) {
        if self.scan_task.is_some() {
            return;
        }
        let Some(h) = self.attached.clone() else {
            return;
        };
        if !self.scanner.has_scanned {
            self.status = "Faca um First Scan antes.".into();
            return;
        }

        if self.value_type.is_string() {
            self.start_string_scan(h, true);
            return;
        }

        let target = self.parse_target();
        if self.scan_kind.needs_value() && target.is_none() {
            self.status = "Valor invalido.".into();
            return;
        }

        let current = std::mem::take(&mut self.scanner.matches);
        let progress = ScanProgress::new(current.len());
        let (tx, rx) = std::sync::mpsc::channel();

        let value_type = self.value_type;
        let kind = self.scan_kind;
        let target = target.unwrap_or(0.0);
        let prog = progress.clone();
        std::thread::spawn(move || {
            let result =
                scan::next_scan_job(h.raw(), current, value_type, kind, target, &prog);
            let _ = tx.send(result);
        });

        self.scan_task = Some(ScanTask {
            progress,
            rx,
            is_next: true,
        });
        self.status = "Next scan em andamento...".into();
    }

    fn refresh_module_bases(&mut self, pid: u32) {
        self.module_bases.clear();
        for m in inject::list_modules(pid) {
            self.module_bases.entry(m.name).or_insert(m.base);
        }
    }

    /// Endereco efetivo de uma entrada: fixo, ou resolvido pela cadeia de ponteiros.
    fn entry_address(&self, e: &SavedEntry) -> Option<u64> {
        let h = self.attached.as_ref()?;
        match &e.pointer {
            None => Some(e.address),
            Some(path) => {
                let base = *self.module_bases.get(&path.module)?;
                pointer::resolve(h.raw(), base, path)
            }
        }
    }

    fn do_pointer_scan(&mut self) {
        if self.ptr_task.is_some() {
            return;
        }
        let Some(h) = self.attached.clone() else {
            self.status = "Anexe um processo primeiro.".into();
            return;
        };
        let Some(target) = parse_addr(&self.ptr_target_text) else {
            self.status = "Endereco alvo invalido (use hex).".into();
            return;
        };
        let max_offset = self.ptr_max_offset_text.trim().parse::<u64>().unwrap_or(2048);
        let max_depth = self.ptr_depth_text.trim().parse::<usize>().unwrap_or(4).clamp(1, 8);
        let alignment = self.ptr_align_text.trim().parse::<usize>().unwrap_or(4).max(1);

        let regions = memory::enumerate_regions(h.raw());
        let modules = ModuleRanges::from(&inject::list_modules(h.pid));
        let progress = ScanProgress::new(regions.len());
        let (tx, rx) = std::sync::mpsc::channel();

        let params = PtrScanParams {
            target,
            max_offset,
            max_depth,
            alignment,
            max_results: 5000,
        };
        let prog = progress.clone();
        std::thread::spawn(move || {
            let result = pointer::pointer_scan(h.raw(), &regions, &modules, params, &prog);
            let _ = tx.send(result);
        });

        self.ptr_task = Some(PtrTask { progress, rx });
        self.status = "Pointer scan em andamento...".into();
    }

    fn poll_ptr_task(&mut self) {
        let Some(task) = &self.ptr_task else {
            return;
        };
        match task.rx.try_recv() {
            Ok(result) => {
                self.status = format!("Pointer scan: {} cadeias encontradas.", result.len());
                self.ptr_results = result;
                self.ptr_task = None;
            }
            Err(TryRecvError::Disconnected) => {
                self.status = "Pointer scan interrompido.".into();
                self.ptr_task = None;
            }
            Err(TryRecvError::Empty) => {}
        }
    }

    /// Verifica se a busca em andamento terminou e recolhe o resultado.
    fn poll_scan_task(&mut self) {
        let Some(task) = &self.scan_task else {
            return;
        };
        match task.rx.try_recv() {
            Ok(result) => {
                let is_next = task.is_next;
                self.scanner.matches = result;
                self.scanner.has_scanned = true;
                self.status = format!(
                    "{}: {} resultados.",
                    if is_next { "Next scan" } else { "First scan" },
                    self.scanner.matches.len()
                );
                self.scan_task = None;
            }
            Err(TryRecvError::Disconnected) => {
                self.status = "Busca interrompida (thread encerrou).".into();
                self.scan_task = None;
            }
            Err(TryRecvError::Empty) => {}
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_scan_task();
        self.poll_ptr_task();
        self.poll_repeater();
        // repinta rapido durante a busca; medio com o proxy ativo; devagar ocioso
        if self.scan_task.is_some() || self.ptr_task.is_some() {
            ctx.request_repaint_after(Duration::from_millis(60));
        } else if self.proxy.is_some() {
            ctx.request_repaint_after(Duration::from_millis(150));
        } else {
            ctx.request_repaint_after(Duration::from_millis(250));
        }

        if self.show_process_picker {
            self.process_picker(ctx);
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Selecionar processo").clicked() {
                    self.processes = process::list_processes();
                    self.show_process_picker = true;
                }
                ui.separator();
                if self.attached.is_some() {
                    ui.colored_label(egui::Color32::LIGHT_GREEN, &self.attached_name);
                } else {
                    ui.colored_label(egui::Color32::GRAY, "(sem processo)");
                }
                ui.separator();
                self.protection_badge(ui);
            });

            ui.horizontal(|ui| {
                // Seletor de secao. Mudar de secao ajusta a aba ativa.
                if ui
                    .selectable_label(self.section == Section::Kernel, "🛡 Kernel Exploring")
                    .clicked()
                {
                    self.section = Section::Kernel;
                    self.tab = Tab::KernelOverview;
                }
                let general_resp = ui.selectable_label(
                    self.section == Section::General,
                    "🔧 General Exploring",
                );
                if general_resp.clicked() {
                    self.section = Section::General;
                    if self.tab.section() != Section::General {
                        self.tab = Tab::Busca;
                    }
                }
                if self.injection_blocked() {
                    general_resp.on_hover_text(
                        "Anticheat kernel detectado — acesso direto ao processo bloqueado. \
                         Use Kernel Exploring.",
                    );
                }
            });

            ui.separator();
            ui.horizontal(|ui| match self.section {
                Section::General => {
                    ui.selectable_value(&mut self.tab, Tab::Busca, "Busca");
                    ui.selectable_value(&mut self.tab, Tab::Pointer, "Pointer Scan");
                    ui.selectable_value(&mut self.tab, Tab::Assembler, "Auto Assembler");
                    ui.selectable_value(&mut self.tab, Tab::Injecao, "Injeção");
                }
                Section::Kernel => {
                    ui.selectable_value(&mut self.tab, Tab::Proxy, "Proxy HTTPS");
                    ui.selectable_value(&mut self.tab, Tab::KernelOverview, "Visão geral");
                    ui.weak("Captura passiva · LCU  (em construção)");
                }
            });
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.label(&self.status);
        });

        egui::SidePanel::right("table")
            .resizable(true)
            .default_width(420.0)
            .show(ctx, |ui| {
                self.saved_table(ui);
            });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Busca => self.scan_panel(ui),
            Tab::Pointer => self.pointer_panel(ui),
            Tab::Assembler => self.assembler_panel(ui),
            Tab::Injecao => self.inject_panel(ui),
            Tab::Proxy => self.proxy_panel(ui),
            Tab::KernelOverview => self.kernel_panel(ui),
        });
    }
}

impl App {
    fn process_picker(&mut self, ctx: &egui::Context) {
        let mut open = true;
        let mut chosen: Option<(u32, String)> = None;
        egui::Window::new("Selecionar processo")
            .open(&mut open)
            .resizable(true)
            .default_size([400.0, 500.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Filtro:");
                    ui.text_edit_singleline(&mut self.proc_filter);
                    if ui.button("Atualizar").clicked() {
                        self.processes = process::list_processes();
                    }
                });
                ui.separator();
                let filter = self.proc_filter.to_lowercase();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for p in &self.processes {
                        if !filter.is_empty() && !p.name.to_lowercase().contains(&filter) {
                            continue;
                        }
                        if ui
                            .button(format!("{}  —  pid {}", p.name, p.pid))
                            .clicked()
                        {
                            chosen = Some((p.pid, p.name.clone()));
                        }
                    }
                });
            });
        if let Some((pid, name)) = chosen {
            self.attach(pid, name);
            self.show_process_picker = false;
        }
        if !open {
            self.show_process_picker = false;
        }
    }

    fn scan_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Busca de valores");
        ui.add_space(4.0);

        let is_string = self.value_type.is_string();
        if is_string {
            // strings so suportam busca por texto exato
            self.scan_kind = ScanKind::Exact;
        }

        egui::Grid::new("scan_controls")
            .num_columns(2)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label("Tipo:");
                egui::ComboBox::from_id_source("vt")
                    .selected_text(self.value_type.label())
                    .show_ui(ui, |ui| {
                        for vt in ValueType::ALL {
                            ui.selectable_value(&mut self.value_type, vt, vt.label());
                        }
                    });
                ui.end_row();

                ui.label("Comparacao:");
                if is_string {
                    ui.add_enabled(false, egui::Button::new("Texto exato"));
                } else {
                    egui::ComboBox::from_id_source("sk")
                        .selected_text(scan_kind_label(self.scan_kind))
                        .show_ui(ui, |ui| {
                            use ScanKind::*;
                            for k in [
                                Exact, BiggerThan, SmallerThan, Changed, Unchanged, Increased,
                                Decreased,
                            ] {
                                ui.selectable_value(&mut self.scan_kind, k, scan_kind_label(k));
                            }
                        });
                }
                ui.end_row();

                ui.label(if is_string { "Texto:" } else { "Valor:" });
                ui.add_enabled(
                    is_string || self.scan_kind.needs_value(),
                    egui::TextEdit::singleline(&mut self.value_text),
                );
                ui.end_row();
            });

        ui.add_enabled_ui(!is_string, |ui| {
            ui.checkbox(&mut self.fast_scan, "Fast scan (alinhado — mais rapido)");
        });

        ui.add_space(6.0);
        let scanning = self.scan_task.is_some();
        ui.horizontal(|ui| {
            let enabled = self.attached.is_some() && !scanning;
            if ui
                .add_enabled(enabled, egui::Button::new("First Scan"))
                .clicked()
            {
                self.do_first_scan();
            }
            if ui
                .add_enabled(
                    enabled && self.scanner.has_scanned,
                    egui::Button::new("Next Scan"),
                )
                .clicked()
            {
                self.do_next_scan();
            }
            if ui
                .add_enabled(!scanning, egui::Button::new("Nova busca"))
                .clicked()
            {
                self.scanner.reset();
                self.status = "Busca limpa.".into();
            }
        });

        if let Some(task) = &self.scan_task {
            let frac = task.progress.fraction();
            ui.add(
                egui::ProgressBar::new(frac)
                    .show_percentage()
                    .text(format!("{} encontrados", task.progress.matches_count())),
            );
            if ui.button("Cancelar").clicked() {
                task.progress.request_cancel();
            }
        }

        ui.separator();
        let total = self.scanner.matches.len();
        ui.label(format!("Resultados: {total} (mostrando ate 1000)"));

        // comprimento de leitura: fixo para numeros, tamanho do texto para strings
        let read_len = if is_string {
            self.value_type
                .parse_to_bytes(&self.value_text)
                .map(|b| b.len())
                .unwrap_or(0)
        } else {
            self.value_type.size()
        };

        let handle = self.attached.clone();
        let mut add_addr: Option<(u64, ValueType, usize)> = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("results")
                .num_columns(3)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Endereco");
                    ui.strong("Valor atual");
                    ui.strong("");
                    ui.end_row();
                    for m in self.scanner.matches.iter().take(1000) {
                        ui.monospace(format!("{:016X}", m.address));
                        let cur = if read_len == 0 {
                            "?".into()
                        } else {
                            handle
                                .as_ref()
                                .and_then(|h| memory::read_bytes(h.raw(), m.address, read_len))
                                .map(|b| self.value_type.format(&b))
                                .unwrap_or_else(|| "?".into())
                        };
                        ui.monospace(cur);
                        if ui.small_button("+ tabela").clicked() {
                            add_addr = Some((m.address, self.value_type, read_len));
                        }
                        ui.end_row();
                    }
                });
        });

        if let Some((address, vt, str_len)) = add_addr {
            self.saved.push(SavedEntry {
                address,
                value_type: vt,
                desc: String::new(),
                frozen: false,
                edit_text: String::new(),
                pointer: None,
                str_len,
            });
        }
    }

    fn saved_table(&mut self, ui: &mut egui::Ui) {
        ui.heading("Cheat Table");
        ui.label("Enderecos salvos — edite, escreva e congele valores.");
        ui.separator();

        let handle = self.attached.clone();
        // resolve os enderecos (fixos ou via ponteiro) antes do loop mutavel
        let addrs: Vec<Option<u64>> = self.saved.iter().map(|e| self.entry_address(e)).collect();

        let mut remove: Option<usize> = None;
        let mut write_idx: Option<usize> = None;
        let mut ptr_scan_target: Option<u64> = None;
        let mut frozen_changed = false;

        egui::ScrollArea::vertical().show(ui, |ui| {
            for (i, e) in self.saved.iter_mut().enumerate() {
                let resolved = addrs[i];
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        match resolved {
                            Some(a) => ui.monospace(format!("{a:016X}")),
                            None => ui.colored_label(egui::Color32::DARK_RED, "??? (não resolvido)"),
                        };
                        ui.label(format!("[{}]", e.value_type.label()));
                        if ui.small_button("x").clicked() {
                            remove = Some(i);
                        }
                    });
                    if let Some(p) = &e.pointer {
                        ui.monospace(egui::RichText::new(p.format()).small());
                    }
                    ui.horizontal(|ui| {
                        ui.label("Desc:");
                        ui.text_edit_singleline(&mut e.desc);
                    });
                    ui.horizontal(|ui| {
                        let len = e.read_len();
                        let cur = if len == 0 {
                            "?".into()
                        } else {
                            handle
                                .as_ref()
                                .zip(resolved)
                                .and_then(|(h, a)| memory::read_bytes(h.raw(), a, len))
                                .map(|b| e.value_type.format(&b))
                                .unwrap_or_else(|| "?".into())
                        };
                        ui.label("Atual:");
                        ui.monospace(cur);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Novo:");
                        ui.text_edit_singleline(&mut e.edit_text);
                        if ui.button("Escrever").clicked() {
                            write_idx = Some(i);
                        }
                        if ui.checkbox(&mut e.frozen, "Congelar").changed() {
                            frozen_changed = true;
                        }
                    });
                    if e.pointer.is_none() {
                        if let Some(a) = resolved {
                            if ui.small_button("pointer scan deste endereço").clicked() {
                                ptr_scan_target = Some(a);
                            }
                        }
                    }
                });
            }
        });

        if let Some(i) = remove {
            self.saved.remove(i);
            self.rebuild_frozen_targets();
        }
        if let Some(i) = write_idx {
            let addr = addrs.get(i).copied().flatten();
            if let (Some(h), Some(e), Some(a)) = (handle.as_ref(), self.saved.get(i), addr) {
                if let Some(bytes) = e.value_type.parse_to_bytes(&e.edit_text) {
                    if memory::write_bytes(h.raw(), a, &bytes) {
                        self.status = format!("Escrito em {a:016X}.");
                    } else {
                        self.status = "Falha ao escrever (protecao de memoria?).".into();
                    }
                } else {
                    self.status = "Valor a escrever invalido.".into();
                }
            }
        }
        if let Some(a) = ptr_scan_target {
            self.ptr_target_text = format!("{a:X}");
            self.tab = Tab::Pointer;
            self.status = format!("Alvo do pointer scan: {a:X}. Ajuste e clique Procurar.");
        }
        if frozen_changed {
            self.rebuild_frozen_targets();
        }
    }

    fn pointer_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Pointer Scan");
        ui.label(
            "Acha cadeias estáveis (módulo.exe+offset → +o1 → +o2 …) que sempre levam ao endereço, \
             mesmo reiniciando o jogo.",
        );
        ui.add_space(4.0);

        let scanning = self.ptr_task.is_some();
        egui::Grid::new("ptr_ctrl")
            .num_columns(2)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label("Endereço alvo (hex):");
                ui.add_enabled(
                    !scanning,
                    egui::TextEdit::singleline(&mut self.ptr_target_text),
                );
                ui.end_row();
                ui.label("Offset máximo:");
                ui.add_enabled(
                    !scanning,
                    egui::TextEdit::singleline(&mut self.ptr_max_offset_text),
                );
                ui.end_row();
                ui.label("Profundidade máx (1-8):");
                ui.add_enabled(
                    !scanning,
                    egui::TextEdit::singleline(&mut self.ptr_depth_text),
                );
                ui.end_row();
                ui.label("Alinhamento:");
                ui.add_enabled(
                    !scanning,
                    egui::TextEdit::singleline(&mut self.ptr_align_text),
                );
                ui.end_row();
            });

        ui.horizontal(|ui| {
            let enabled = self.attached.is_some() && !scanning;
            if ui
                .add_enabled(enabled, egui::Button::new("Procurar cadeias"))
                .clicked()
            {
                self.do_pointer_scan();
            }
            if ui
                .add_enabled(!scanning, egui::Button::new("Limpar"))
                .clicked()
            {
                self.ptr_results.clear();
            }
        });

        if let Some(task) = &self.ptr_task {
            ui.add(
                egui::ProgressBar::new(task.progress.fraction())
                    .show_percentage()
                    .text(format!("{} cadeias", task.progress.matches_count())),
            );
            if ui.button("Cancelar").clicked() {
                task.progress.request_cancel();
            }
        }

        ui.separator();
        ui.label(format!(
            "Cadeias encontradas: {} (mostrando até 500). Quanto mais curtas e com offsets pequenos, \
             mais confiáveis.",
            self.ptr_results.len()
        ));

        let handle = self.attached.clone();
        let mut add_path: Option<PtrPath> = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for path in self.ptr_results.iter().take(500) {
                ui.horizontal(|ui| {
                    // valor atual que a cadeia resolve agora (verificacao)
                    let resolved = handle.as_ref().and_then(|h| {
                        self.module_bases
                            .get(&path.module)
                            .and_then(|b| pointer::resolve(h.raw(), *b, path))
                    });
                    let tag = match resolved {
                        Some(a) => format!("→ {a:X}"),
                        None => "→ ?".into(),
                    };
                    if ui.small_button("+ tabela").clicked() {
                        add_path = Some(path.clone());
                    }
                    ui.monospace(path.format());
                    ui.weak(tag);
                });
            }
        });

        if let Some(path) = add_path {
            self.saved.push(SavedEntry {
                address: 0,
                value_type: self.value_type,
                desc: format!("ptr {}", path.module),
                frozen: false,
                edit_text: String::new(),
                pointer: Some(path),
                str_len: 0,
            });
            self.status = "Cadeia adicionada à cheat table (endereço resolvido dinamicamente).".into();
        }
    }

    fn run_assembler(&mut self, section: assembler::Section) {
        let Some(h) = self.attached.clone() else {
            self.status = "Anexe um processo primeiro.".into();
            return;
        };
        let name = if section == assembler::Section::Enable {
            "Enable"
        } else {
            "Disable"
        };
        match assembler::run_section(h.raw(), h.pid, &self.aa_script, section, &mut self.aa_state) {
            Ok(log) => {
                self.status = format!("{name} executado ({} passos).", log.len());
                self.aa_log = log;
            }
            Err(e) => {
                self.status = format!("{name} falhou: {e}");
                self.aa_log = vec![format!("ERRO: {e}")];
            }
        }
    }

    fn assembler_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Auto Assembler");
        if self.injection_blocked() {
            let name = self
                .detection
                .as_ref()
                .and_then(|d| d.protection.ac_name())
                .unwrap_or("anticheat kernel");
            ui.colored_label(
                egui::Color32::from_rgb(0xE0, 0x6C, 0x75),
                format!("🛡 {name} detectado — patch de código bloqueado. Use Kernel Exploring."),
            );
            return;
        }
        ui.label(
            "Scripts estilo Cheat Engine: AOB scan, code cave (alloc), patch e restauração. \
             Enable aplica, Disable desfaz.",
        );

        let enabled = self.attached.is_some();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(enabled, egui::Button::new("▶ Enable"))
                .clicked()
            {
                self.run_assembler(assembler::Section::Enable);
            }
            if ui
                .add_enabled(enabled, egui::Button::new("■ Disable"))
                .clicked()
            {
                self.run_assembler(assembler::Section::Disable);
            }
            if ui.button("Restaurar template").clicked() {
                self.aa_script = AA_TEMPLATE.to_string();
            }
        });

        ui.separator();
        egui::ScrollArea::vertical()
            .id_source("aa_editor")
            .max_height(360.0)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.aa_script)
                        .code_editor()
                        .desired_rows(18)
                        .desired_width(f32::INFINITY),
                );
            });

        ui.separator();
        ui.label("Log:");
        egui::ScrollArea::vertical()
            .id_source("aa_log")
            .max_height(160.0)
            .show(ui, |ui| {
                for l in &self.aa_log {
                    ui.monospace(l);
                }
            });
    }

    /// Badge colorido no top bar com o resultado da classificacao de AC.
    fn protection_badge(&self, ui: &mut egui::Ui) {
        match self.detection.as_ref().map(|d| &d.protection) {
            None => {
                ui.colored_label(egui::Color32::GRAY, "Proteção: —");
            }
            Some(anticheat::Protection::KernelAc(name)) => {
                ui.colored_label(
                    egui::Color32::from_rgb(0xE0, 0x6C, 0x75),
                    format!("🛡 AC kernel: {name} (injeção bloqueada)"),
                );
            }
            Some(anticheat::Protection::UsermodeAc(name)) => {
                ui.colored_label(
                    egui::Color32::from_rgb(0xE5, 0xC0, 0x7B),
                    format!("⚠ AC user-mode: {name}"),
                );
            }
            Some(anticheat::Protection::Unprotected) => {
                ui.colored_label(egui::Color32::LIGHT_GREEN, "✔ Sem AC kernel");
            }
        }
    }

    /// Painel da secao Kernel Exploring: mostra a classificacao e os metodos
    /// safe disponiveis (que nao tocam o processo protegido).
    fn kernel_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("🛡 Kernel Exploring (safe)");
        ui.label(
            "Análise de alvos protegidos por anticheat kernel (Vanguard, EAC, BattlEye…) \
             SEM injeção nem acesso ao processo — só métodos que respeitam o anticheat.",
        );
        ui.add_space(6.0);

        ui.group(|ui| {
            ui.strong("Classificação do alvo");
            match self.detection.as_ref() {
                None => {
                    ui.label("Anexe um processo para classificar.");
                }
                Some(det) => {
                    self.protection_badge(ui);
                    if det.reasons.is_empty() {
                        ui.weak("Nenhuma assinatura de anticheat encontrada.");
                    } else {
                        for r in &det.reasons {
                            ui.weak(format!("• {r}"));
                        }
                    }
                }
            }
        });

        ui.add_space(6.0);
        ui.strong("Métodos disponíveis");
        let method = |ui: &mut egui::Ui, name: &str, desc: &str, ready: bool| {
            ui.horizontal(|ui| {
                if ready {
                    ui.colored_label(egui::Color32::LIGHT_GREEN, "●");
                } else {
                    ui.colored_label(egui::Color32::GRAY, "○");
                }
                ui.strong(name);
                ui.weak(if ready { "" } else { "(em construção)" });
            });
            ui.weak(desc);
            ui.add_space(2.0);
        };
        method(
            ui,
            "Proxy HTTPS + CA própria",
            "Intercepta as APIs web/plataforma (login, loja, matchmaking) em texto puro — \
             estilo Burp, sem tocar no jogo.",
            false,
        );
        method(
            ui,
            "Captura passiva (pcap)",
            "Observa endpoints, portas, timing e volume na placa de rede. Conteúdo cifrado, \
             mas ótimo para Threat Intel / mapeamento de infra.",
            false,
        );
        method(
            ui,
            "API local do client (LCU)",
            "Fala com a REST/WebSocket local do client (ex.: League) — acessível \
             legitimamente, sem injeção.",
            false,
        );
    }

    fn proxy_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Proxy HTTPS");
        ui.label(
            "Intercepta, edita e reenvia requisições/respostas HTTP(S) — estilo Burp. Não toca \
             no processo: funciona com qualquer alvo, inclusive sob anticheat kernel.",
        );
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            let running = self.proxy.is_some();
            ui.label("Porta:");
            ui.add_enabled(
                !running,
                egui::TextEdit::singleline(&mut self.proxy_port_text).desired_width(70.0),
            );
            if !running {
                if ui.button("▶ Iniciar").clicked() {
                    match self.proxy_port_text.trim().parse::<u16>() {
                        Ok(port) => {
                            let p = proxy::start(port);
                            p.shared.set_rules(self.rules.clone());
                            self.proxy = Some(p);
                            self.status = format!("Proxy iniciado na porta {port}.");
                        }
                        Err(_) => self.status = "Porta inválida.".into(),
                    }
                }
            } else if ui.button("■ Parar").clicked() {
                self.proxy = None; // Drop encerra o proxy
                self.status = "Proxy parado.".into();
            }
            if let Some(p) = &self.proxy {
                ui.colored_label(egui::Color32::LIGHT_GREEN, p.status());
            }
        });

        if let Some(p) = &self.proxy {
            ui.horizontal(|ui| {
                ui.label("CA:");
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(p.ca_path.display().to_string()).monospace(),
                    )
                    .selectable(true),
                );
            });
            ui.weak(
                "Instale esse arquivo como Autoridade Certificadora Raiz confiável e aponte o \
                 proxy do sistema/jogo para 127.0.0.1 na porta acima para ver HTTPS.",
            );
        }

        ui.separator();
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.proxy_view, ProxyView::History, "Histórico");
            let pending = self.proxy.as_ref().map(|p| p.shared.pending_count()).unwrap_or(0);
            let label = if pending > 0 {
                format!("Intercept ({pending})")
            } else {
                "Intercept".to_string()
            };
            ui.selectable_value(&mut self.proxy_view, ProxyView::Intercept, label);
            ui.selectable_value(&mut self.proxy_view, ProxyView::Repeater, "Repeater");
            ui.selectable_value(&mut self.proxy_view, ProxyView::Rules, "Match & Replace");
        });
        ui.separator();

        match self.proxy_view {
            ProxyView::History => self.proxy_history(ui),
            ProxyView::Intercept => self.proxy_intercept(ui),
            ProxyView::Repeater => self.proxy_repeater(ui),
            ProxyView::Rules => self.proxy_rules(ui),
        }
    }

    fn proxy_history(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Filtro:");
            ui.text_edit_singleline(&mut self.proxy_filter);
            if ui.button("Limpar histórico").clicked() {
                if let Some(p) = &self.proxy {
                    p.shared.flows.lock().unwrap().clear();
                }
                self.proxy_selected = None;
            }
        });

        let flows: Vec<proxy::FlowRecord> = self
            .proxy
            .as_ref()
            .map(|p| p.shared.flows.lock().unwrap().clone())
            .unwrap_or_default();
        let filter = self.proxy_filter.to_lowercase();
        ui.label(format!("{} flows", flows.len()));

        egui::ScrollArea::vertical()
            .id_source("proxy_flows")
            .max_height(220.0)
            .show(ui, |ui| {
                egui::Grid::new("proxy_grid")
                    .striped(true)
                    .num_columns(4)
                    .show(ui, |ui| {
                        ui.strong("#");
                        ui.strong("Método");
                        ui.strong("Status");
                        ui.strong("URL");
                        ui.end_row();
                        for f in flows.iter().rev() {
                            if !filter.is_empty() && !f.url.to_lowercase().contains(&filter) {
                                continue;
                            }
                            let sel = self.proxy_selected == Some(f.id);
                            if ui.selectable_label(sel, f.id.to_string()).clicked() {
                                self.proxy_selected = Some(f.id);
                            }
                            ui.label(&f.method);
                            ui.label(if f.status == 0 {
                                "—".to_string()
                            } else {
                                f.status.to_string()
                            });
                            ui.label(&f.url);
                            ui.end_row();
                        }
                    });
            });

        let selected = self
            .proxy_selected
            .and_then(|id| flows.iter().find(|f| f.id == id).cloned());
        if let Some(f) = selected {
            ui.separator();
            ui.horizontal(|ui| {
                ui.strong(format!(
                    "{} {}  →  {}  ({} B req / {} B resp)",
                    f.method, f.url, f.status, f.req_len, f.resp_len
                ));
                if ui.button("→ Repeater").clicked() {
                    self.rep_method = f.method.clone();
                    self.rep_url = f.url.clone();
                    self.rep_headers = f.req_headers.clone();
                    self.rep_body = f.req_body.clone();
                    self.proxy_view = ProxyView::Repeater;
                }
            });
            egui::ScrollArea::vertical()
                .id_source("proxy_detail")
                .show(ui, |ui| {
                    ui.collapsing("Requisição", |ui| {
                        ui.monospace(&f.req_headers);
                        if !f.req_body.is_empty() {
                            ui.separator();
                            ui.monospace(&f.req_body);
                        }
                    });
                    ui.collapsing("Resposta", |ui| {
                        ui.monospace(&f.resp_headers);
                        if !f.resp_body.is_empty() {
                            ui.separator();
                            ui.monospace(&f.resp_body);
                        }
                    });
                });
        }
    }

    fn proxy_intercept(&mut self, ui: &mut egui::Ui) {
        let Some(shared) = self.proxy.as_ref().map(|p| p.shared.clone()) else {
            ui.weak("Inicie o proxy para interceptar.");
            return;
        };

        let mut on = shared.intercept_on();
        if ui
            .checkbox(&mut on, "Interceptar (pausar requisições antes de enviar)")
            .changed()
        {
            shared.set_intercept(on);
        }
        ui.separator();

        let Some(view) = shared.first_pending() else {
            ui.weak(if on {
                "Aguardando requisição…"
            } else {
                "Intercept desligado."
            });
            return;
        };

        // Carrega os buffers editáveis quando chega um item novo.
        if self.icpt_id != Some(view.id) {
            self.icpt_id = Some(view.id);
            self.icpt_headers = view.headers.clone();
            self.icpt_body = view.body.clone();
            self.icpt_follow = false;
        }

        let is_req = view.kind == proxy::InterceptKind::Request;
        ui.strong(format!(
            "{} — {} {}",
            if is_req { "Requisição" } else { "Resposta" },
            view.method,
            view.url
        ));
        if !is_req {
            ui.label(format!("Status {}", view.status));
        }

        ui.label("Headers:");
        ui.add(
            egui::TextEdit::multiline(&mut self.icpt_headers)
                .code_editor()
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
        ui.label("Body:");
        ui.add(
            egui::TextEdit::multiline(&mut self.icpt_body)
                .code_editor()
                .desired_rows(8)
                .desired_width(f32::INFINITY),
        );
        if is_req {
            ui.checkbox(&mut self.icpt_follow, "Interceptar a resposta também");
        }

        let mut forward = false;
        let mut forward_follow = false;
        let mut drop = false;
        let mut to_repeater = false;
        ui.horizontal(|ui| {
            let fwd = ui.button("▶ Forward");
            if is_req {
                fwd.context_menu(|ui| {
                    if ui.button("Forward interceptando a resposta").clicked() {
                        forward_follow = true;
                        ui.close_menu();
                    }
                });
            }
            if fwd.clicked() {
                forward = true;
            }
            if ui.button("✖ Drop").clicked() {
                drop = true;
            }
            if is_req && ui.button("→ Repeater").clicked() {
                to_repeater = true;
            }
        });

        if forward || forward_follow {
            shared.resolve(
                view.id,
                proxy::Decision::Forward {
                    headers: self.icpt_headers.clone(),
                    body: self.icpt_body.clone(),
                    intercept_response: self.icpt_follow || forward_follow,
                },
            );
            self.icpt_id = None;
        } else if drop {
            shared.resolve(view.id, proxy::Decision::Drop);
            self.icpt_id = None;
        }
        if to_repeater {
            self.rep_method = view.method.clone();
            self.rep_url = view.url.clone();
            self.rep_headers = self.icpt_headers.clone();
            self.rep_body = self.icpt_body.clone();
            self.proxy_view = ProxyView::Repeater;
        }
    }

    fn proxy_repeater(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Método:");
            ui.add(egui::TextEdit::singleline(&mut self.rep_method).desired_width(70.0));
            ui.label("URL:");
            ui.add(
                egui::TextEdit::singleline(&mut self.rep_url).desired_width(f32::INFINITY),
            );
        });
        ui.label("Headers:");
        ui.add(
            egui::TextEdit::multiline(&mut self.rep_headers)
                .code_editor()
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
        ui.label("Body:");
        ui.add(
            egui::TextEdit::multiline(&mut self.rep_body)
                .code_editor()
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );

        ui.horizontal(|ui| {
            let can = self.proxy.is_some() && !self.rep_busy;
            if ui.add_enabled(can, egui::Button::new("▶ Enviar")).clicked() {
                let rx = self.proxy.as_ref().map(|p| {
                    p.repeater(
                        self.rep_method.clone(),
                        self.rep_url.clone(),
                        self.rep_headers.clone(),
                        self.rep_body.clone(),
                    )
                });
                if let Some(rx) = rx {
                    self.rep_rx = Some(rx);
                    self.rep_busy = true;
                }
            }
            if self.proxy.is_none() {
                ui.weak("(inicie o proxy para usar o Repeater)");
            }
            if self.rep_busy {
                ui.spinner();
                ui.label("enviando…");
            }
        });

        ui.separator();
        ui.strong(format!(
            "Resposta: {}",
            if self.rep_status == 0 {
                "—".to_string()
            } else {
                self.rep_status.to_string()
            }
        ));
        egui::ScrollArea::vertical()
            .id_source("rep_resp")
            .show(ui, |ui| {
                if !self.rep_resp_headers.is_empty() {
                    ui.monospace(&self.rep_resp_headers);
                    ui.separator();
                }
                if !self.rep_resp_body.is_empty() {
                    ui.monospace(&self.rep_resp_body);
                }
            });
    }

    fn proxy_rules(&mut self, ui: &mut egui::Ui) {
        ui.label(
            "Regras aplicadas automaticamente a toda mensagem (ex.: trocar dano=10 por \
             dano=9999). Substring ou regex.",
        );
        if ui.button("+ Nova regra").clicked() {
            self.rules.push(proxy::Rule {
                enabled: true,
                target: proxy::RuleTarget::RequestBody,
                is_regex: false,
                pattern: String::new(),
                replacement: String::new(),
            });
        }
        ui.separator();

        let mut remove: Option<usize> = None;
        egui::ScrollArea::vertical()
            .id_source("rules")
            .show(ui, |ui| {
                for (i, r) in self.rules.iter_mut().enumerate() {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut r.enabled, "ativa");
                            egui::ComboBox::from_id_source(format!("rt{i}"))
                                .selected_text(r.target.label())
                                .show_ui(ui, |ui| {
                                    for t in proxy::RuleTarget::ALL {
                                        ui.selectable_value(&mut r.target, t, t.label());
                                    }
                                });
                            ui.checkbox(&mut r.is_regex, "regex");
                            if ui.small_button("x").clicked() {
                                remove = Some(i);
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.label("Match:  ");
                            ui.add(
                                egui::TextEdit::singleline(&mut r.pattern)
                                    .desired_width(f32::INFINITY),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label("Replace:");
                            ui.add(
                                egui::TextEdit::singleline(&mut r.replacement)
                                    .desired_width(f32::INFINITY),
                            );
                        });
                    });
                }
            });
        if let Some(i) = remove {
            self.rules.remove(i);
        }

        // Sincroniza as regras com o runtime do proxy.
        if let Some(p) = &self.proxy {
            p.shared.set_rules(self.rules.clone());
        }
    }

    fn inject_panel(&mut self, ui: &mut egui::Ui) {
        let Some(h) = self.attached.clone() else {
            ui.heading("Injeção");
            ui.label("Anexe um processo primeiro (botão acima).");
            return;
        };
        // Trava de seguranca: com AC kernel, nao oferecemos injecao/patch.
        if self.injection_blocked() {
            ui.heading("Injeção");
            let name = self
                .detection
                .as_ref()
                .and_then(|d| d.protection.ac_name())
                .unwrap_or("anticheat kernel");
            ui.colored_label(
                egui::Color32::from_rgb(0xE0, 0x6C, 0x75),
                format!("🛡 {name} detectado — injeção e patch bloqueados."),
            );
            ui.label(
                "Injetar ou modificar este processo seria detectado/banido e foge do escopo \
                 da ferramenta. Use a seção Kernel Exploring para análise safe.",
            );
            if ui.button("Ir para Kernel Exploring").clicked() {
                self.section = Section::Kernel;
                self.tab = Tab::KernelOverview;
            }
            return;
        }
        let pid = h.pid;

        egui::ScrollArea::vertical().show(ui, |ui| {
            // ---------- Módulos ----------
            ui.heading("Módulos carregados");
            ui.horizontal(|ui| {
                if ui.button("Listar módulos").clicked() {
                    self.modules = inject::list_modules(pid);
                    self.status = format!("{} módulos.", self.modules.len());
                }
                ui.label("Filtro:");
                ui.text_edit_singleline(&mut self.module_filter);
            });
            let mf = self.module_filter.to_lowercase();
            egui::ScrollArea::vertical()
                .id_source("mods")
                .max_height(160.0)
                .show(ui, |ui| {
                    egui::Grid::new("modgrid").striped(true).num_columns(3).show(ui, |ui| {
                        ui.strong("Módulo");
                        ui.strong("Base");
                        ui.strong("Tamanho");
                        ui.end_row();
                        for m in &self.modules {
                            if !mf.is_empty() && !m.name.to_lowercase().contains(&mf) {
                                continue;
                            }
                            ui.label(&m.name);
                            ui.monospace(format!("{:016X}", m.base));
                            ui.monospace(format!("{:X}", m.size));
                            ui.end_row();
                        }
                    });
                });

            ui.separator();

            // ---------- AOB scan ----------
            ui.heading("AOB scan (padrão de bytes)");
            ui.label("Ex: 48 8B 05 ?? ?? ?? ?? 89   (?? = qualquer byte)");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.aob_text);
                if ui.button("Procurar").clicked() {
                    match inject::parse_aob(&self.aob_text) {
                        Some(pat) => {
                            let regions = memory::enumerate_regions(h.raw());
                            self.aob_results = inject::aob_scan(h.raw(), &regions, &pat, 200);
                            self.status =
                                format!("AOB: {} ocorrências.", self.aob_results.len());
                        }
                        None => self.status = "Padrão AOB inválido.".into(),
                    }
                }
            });
            let mut aob_to_patch: Option<u64> = None;
            egui::ScrollArea::vertical()
                .id_source("aob")
                .max_height(140.0)
                .show(ui, |ui| {
                    for a in self.aob_results.iter().take(200) {
                        ui.horizontal(|ui| {
                            ui.monospace(format!("{:016X}", a));
                            if ui.small_button("→ patch").clicked() {
                                aob_to_patch = Some(*a);
                            }
                        });
                    }
                });
            if let Some(a) = aob_to_patch {
                self.patch_addr_text = format!("{a:X}");
                self.nop_addr_text = format!("{a:X}");
            }

            ui.separator();

            // ---------- Patch / NOP ----------
            ui.heading("Patch de bytes / NOP");
            egui::Grid::new("patchgrid").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                ui.label("Endereço (hex):");
                ui.text_edit_singleline(&mut self.patch_addr_text);
                ui.end_row();
                ui.label("Bytes (hex):");
                ui.text_edit_singleline(&mut self.patch_bytes_text);
                ui.end_row();
            });
            ui.horizontal(|ui| {
                if ui.button("Escrever bytes").clicked() {
                    match (
                        parse_addr(&self.patch_addr_text),
                        inject::parse_hex_bytes(&self.patch_bytes_text),
                    ) {
                        (Some(addr), Some(bytes)) => {
                            let ok = inject::write_code(h.raw(), addr, &bytes);
                            self.status = if ok {
                                format!("Patch de {} bytes em {addr:X}.", bytes.len())
                            } else {
                                "Falha no patch.".into()
                            };
                        }
                        _ => self.status = "Endereço ou bytes inválidos.".into(),
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("NOP — endereço:");
                ui.text_edit_singleline(&mut self.nop_addr_text);
                ui.label("qtd:");
                ui.add(egui::TextEdit::singleline(&mut self.nop_len_text).desired_width(50.0));
                if ui.button("NOP").clicked() {
                    match (parse_addr(&self.nop_addr_text), self.nop_len_text.trim().parse::<usize>()) {
                        (Some(addr), Ok(len)) if len > 0 && len <= 256 => {
                            let ok = inject::nop(h.raw(), addr, len);
                            self.status = if ok {
                                format!("{len} NOP(s) em {addr:X}.")
                            } else {
                                "Falha no NOP.".into()
                            };
                        }
                        _ => self.status = "Endereço/quantidade inválidos (1..256).".into(),
                    }
                }
            });

            ui.separator();

            // ---------- Injeção de DLL ----------
            ui.heading("Injeção de DLL");
            ui.horizontal(|ui| {
                ui.label("Caminho .dll:");
                ui.text_edit_singleline(&mut self.dll_path);
            });
            if ui.button("Injetar DLL").clicked() {
                let path = self.dll_path.trim();
                if path.is_empty() || !std::path::Path::new(path).exists() {
                    self.status = "Arquivo .dll não encontrado.".into();
                } else {
                    match inject::inject_dll(h.raw(), path) {
                        Ok(code) if code != 0 => {
                            self.status = format!("DLL injetada (LoadLibrary retornou {code:#X}).")
                        }
                        Ok(_) => {
                            self.status =
                                "CreateRemoteThread rodou mas LoadLibrary retornou 0 (DLL falhou ao carregar — arquitetura x86/x64?)."
                                    .into()
                        }
                        Err(e) => self.status = format!("Falha na injeção: {e}"),
                    }
                }
            }
        });
    }
}

fn scan_kind_label(k: ScanKind) -> &'static str {
    match k {
        ScanKind::Exact => "Valor exato",
        ScanKind::BiggerThan => "Maior que",
        ScanKind::SmallerThan => "Menor que",
        ScanKind::Changed => "Mudou",
        ScanKind::Unchanged => "Nao mudou",
        ScanKind::Increased => "Aumentou",
        ScanKind::Decreased => "Diminuiu",
    }
}
