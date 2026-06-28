//! Instalador gráfico do Quarry (wizard estilo "Next, Next, Install").
//!
//! Auto-extraível: embute o `quarry.exe`, o WinDivert e o ícone via
//! `include_bytes!` e, ao final do assistente, escreve tudo em
//! `%ProgramFiles%\Quarry`, cria os atalhos (menu Iniciar + área de trabalho) e
//! registra a desinstalação. Roda como Administrador (manifesto no build.rs).
//!
//! `quarry-setup.exe --uninstall` abre o desinstalador (a cópia do próprio
//! instalador deixada em `{app}\uninstall.exe`).

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

// --- artefatos embutidos (preparados pelo build-installer.ps1) ---
const QUARRY_EXE: &[u8] = include_bytes!("../../../target/release/quarry.exe");
const WINDIVERT_DLL: &[u8] = include_bytes!("../../../dist/WinDivert/WinDivert.dll");
const WINDIVERT_SYS: &[u8] = include_bytes!("../../../dist/WinDivert/WinDivert64.sys");
const ICON_ICO: &[u8] = include_bytes!("../../../assets/quarry.ico");
const LICENSE_TXT: &[u8] = include_bytes!("../../../LICENSE");

const APP_NAME: &str = "Quarry";
const APP_VERSION: &str = "0.1.0";
const PUBLISHER: &str = "Guilherme Bento";
const UNINSTALL_KEY: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Quarry";

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DETACHED_PROCESS: u32 = 0x0000_0008;

fn main() -> eframe::Result<()> {
    let uninstall = std::env::args().any(|a| a == "--uninstall");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([620.0, 470.0])
            .with_resizable(false),
        ..Default::default()
    };
    if uninstall {
        eframe::run_native(
            "Desinstalar Quarry",
            options,
            Box::new(|_| Ok(Box::<Uninstaller>::default())),
        )
    } else {
        eframe::run_native(
            "Instalador do Quarry",
            options,
            Box::new(|_| Ok(Box::new(Wizard::new()))),
        )
    }
}

// =================== WIZARD (instalação) ===================

#[derive(PartialEq, Clone, Copy)]
enum Step {
    Welcome,
    License,
    Options,
    Installing,
    Done,
}

#[derive(Default)]
struct Progress {
    log: Vec<String>,
    done: bool,
    error: Option<String>,
}

struct Wizard {
    step: Step,
    dir: String,
    desktop: bool,
    launch: bool,
    accepted: bool,
    progress: Arc<Mutex<Progress>>,
    started: bool,
}

impl Wizard {
    fn new() -> Self {
        Self {
            step: Step::Welcome,
            dir: default_dir().to_string_lossy().into_owned(),
            desktop: true,
            launch: true,
            accepted: false,
            progress: Arc::new(Mutex::new(Progress::default())),
            started: false,
        }
    }
}

impl eframe::App for Wizard {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // dispara a instalação ao entrar no passo "Installing"
        if self.step == Step::Installing && !self.started {
            self.started = true;
            let dir = PathBuf::from(self.dir.clone());
            let desktop = self.desktop;
            let progress = self.progress.clone();
            std::thread::spawn(move || do_install(dir, desktop, progress));
        }
        if self.step == Step::Installing {
            ctx.request_repaint();
            if self.progress.lock().unwrap().done {
                self.step = Step::Done;
            }
        }

        // Altura fixa: sem isto, `with_layout` agarra toda a altura disponível e
        // joga os botões para o meio da janela.
        egui::TopBottomPanel::bottom("buttons")
            .exact_height(52.0)
            .show(ctx, |ui| {
                self.button_bar(ui, ctx);
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);
            match self.step {
                Step::Welcome => self.welcome(ui),
                Step::License => self.license(ui),
                Step::Options => self.options(ui),
                Step::Installing => self.installing(ui),
                Step::Done => self.done(ui),
            }
        });
    }
}

impl Wizard {
    fn welcome(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(10.0);
            ui.heading("Bem-vindo ao instalador do Quarry");
        });
        ui.add_space(12.0);
        ui.label(
            "O Quarry é uma ferramenta de análise de jogos e software: scanner/editor de \
             memória e proxy de interceptação HTTPS, com captura de rede e redirect por processo.",
        );
        ui.add_space(8.0);
        ui.label("Este assistente vai:");
        ui.label("   • instalar o Quarry em Program Files;");
        ui.label("   • incluir o driver WinDivert (usado pela aba Redirect);");
        ui.label("   • criar atalhos no menu Iniciar e (opcional) na área de trabalho.");
        ui.add_space(10.0);
        ui.colored_label(
            egui::Color32::from_rgb(0xff, 0xb0, 0x4d),
            "O Quarry precisa de privilégios de Administrador para funcionar.",
        );
        ui.add_space(8.0);
        ui.weak(format!("Versão {APP_VERSION}"));
    }

    fn license(&mut self, ui: &mut egui::Ui) {
        ui.heading("Licença");
        ui.label("Leia e aceite os termos para continuar.");
        ui.add_space(6.0);
        let text = String::from_utf8_lossy(LICENSE_TXT).into_owned();
        egui::ScrollArea::vertical()
            .max_height(280.0)
            .show(ui, |ui| {
                let mut t = text;
                ui.add(
                    egui::TextEdit::multiline(&mut t)
                        .desired_width(f32::INFINITY)
                        .interactive(false),
                );
            });
        ui.add_space(6.0);
        ui.checkbox(&mut self.accepted, "Eu aceito os termos da licença");
    }

    fn options(&mut self, ui: &mut egui::Ui) {
        ui.heading("Opções de instalação");
        ui.add_space(8.0);
        ui.label("Pasta de instalação:");
        ui.add(egui::TextEdit::singleline(&mut self.dir).desired_width(f32::INFINITY));
        ui.add_space(10.0);
        ui.checkbox(&mut self.desktop, "Criar atalho na área de trabalho");
        ui.add_space(10.0);
        ui.weak(
            "O instalador também registra o Quarry em \"Aplicativos instalados\" para \
             desinstalação futura.",
        );
    }

    fn installing(&mut self, ui: &mut egui::Ui) {
        ui.heading("Instalando…");
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Copiando arquivos e criando atalhos…");
        });
        ui.add_space(8.0);
        let log = self.progress.lock().unwrap().log.join("\n");
        egui::ScrollArea::vertical()
            .max_height(280.0)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                ui.monospace(log);
            });
    }

    fn done(&mut self, ui: &mut egui::Ui) {
        let err = self.progress.lock().unwrap().error.clone();
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            match &err {
                None => {
                    ui.heading("✔ Instalação concluída!");
                    ui.add_space(10.0);
                    ui.label("O Quarry foi instalado com sucesso.");
                }
                Some(e) => {
                    ui.colored_label(egui::Color32::LIGHT_RED, "✖ Falha na instalação");
                    ui.add_space(10.0);
                    ui.label(e);
                }
            }
        });
        if err.is_none() {
            ui.add_space(16.0);
            ui.checkbox(&mut self.launch, "Executar o Quarry agora");
        }
    }

    fn button_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            match self.step {
                Step::Welcome => {
                    if ui.button("Próximo ▸").clicked() {
                        self.step = Step::License;
                    }
                    if ui.button("Cancelar").clicked() {
                        std::process::exit(0);
                    }
                }
                Step::License => {
                    if ui
                        .add_enabled(self.accepted, egui::Button::new("Próximo ▸"))
                        .clicked()
                    {
                        self.step = Step::Options;
                    }
                    if ui.button("◂ Voltar").clicked() {
                        self.step = Step::Welcome;
                    }
                    if ui.button("Cancelar").clicked() {
                        std::process::exit(0);
                    }
                }
                Step::Options => {
                    if ui.button("Instalar").clicked() {
                        self.step = Step::Installing;
                    }
                    if ui.button("◂ Voltar").clicked() {
                        self.step = Step::License;
                    }
                    if ui.button("Cancelar").clicked() {
                        std::process::exit(0);
                    }
                }
                Step::Installing => {
                    ui.add_enabled(false, egui::Button::new("Instalar"));
                }
                Step::Done => {
                    if ui.button("Concluir").clicked() {
                        let ok = self.progress.lock().unwrap().error.is_none();
                        if ok && self.launch {
                            let _ = Command::new(PathBuf::from(&self.dir).join("quarry.exe"))
                                .spawn();
                        }
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
        });
    }
}

// =================== execução da instalação ===================

fn do_install(dir: PathBuf, desktop: bool, p: Arc<Mutex<Progress>>) {
    let push = |s: String| p.lock().unwrap().log.push(s);

    let result = (|| -> Result<(), String> {
        push(format!("Criando {}", dir.display()));
        std::fs::create_dir_all(&dir).map_err(|e| format!("criar pasta: {e}"))?;

        for (name, data) in [
            ("quarry.exe", QUARRY_EXE),
            ("WinDivert.dll", WINDIVERT_DLL),
            ("WinDivert64.sys", WINDIVERT_SYS),
            ("quarry.ico", ICON_ICO),
            ("LICENSE.txt", LICENSE_TXT),
        ] {
            push(format!("Gravando {name} ({} KB)", data.len() / 1024));
            std::fs::write(dir.join(name), data).map_err(|e| format!("gravar {name}: {e}"))?;
        }

        // o próprio instalador vira o desinstalador
        push("Preparando o desinstalador".into());
        let me = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        std::fs::copy(&me, dir.join("uninstall.exe"))
            .map_err(|e| format!("copiar desinstalador: {e}"))?;

        push("Criando atalhos".into());
        create_shortcuts(&dir, desktop)?;

        push("Registrando para desinstalação".into());
        write_registry(&dir)?;

        push("Concluído.".into());
        Ok(())
    })();

    let mut g = p.lock().unwrap();
    if let Err(e) = result {
        g.error = Some(e);
    }
    g.done = true;
}

fn create_shortcuts(dir: &Path, desktop: bool) -> Result<(), String> {
    let exe = dir.join("quarry.exe");
    let ico = dir.join("quarry.ico");
    let uninst = dir.join("uninstall.exe");

    let sm = start_menu_dir();
    std::fs::create_dir_all(&sm).map_err(|e| format!("menu Iniciar: {e}"))?;
    make_shortcut(&sm.join("Quarry.lnk"), &exe, "", &ico, dir)?;
    make_shortcut(
        &sm.join("Desinstalar Quarry.lnk"),
        &uninst,
        "--uninstall",
        &ico,
        dir,
    )?;

    if desktop {
        make_shortcut(&public_desktop().join("Quarry.lnk"), &exe, "", &ico, dir)?;
    }
    Ok(())
}

/// Cria um atalho .lnk via WScript.Shell (PowerShell, janela oculta).
fn make_shortcut(lnk: &Path, target: &Path, args: &str, icon: &Path, workdir: &Path) -> Result<(), String> {
    let script = format!(
        "$ws=New-Object -ComObject WScript.Shell;\
         $s=$ws.CreateShortcut('{lnk}');\
         $s.TargetPath='{target}';\
         $s.Arguments='{args}';\
         $s.IconLocation='{icon}';\
         $s.WorkingDirectory='{work}';\
         $s.Save()",
        lnk = lnk.display(),
        target = target.display(),
        args = args,
        icon = icon.display(),
        work = workdir.display(),
    );
    let ok = run_hidden(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
    );
    if ok {
        Ok(())
    } else {
        Err(format!("falha ao criar atalho {}", lnk.display()))
    }
}

fn write_registry(dir: &Path) -> Result<(), String> {
    let exe = dir.join("quarry.exe").to_string_lossy().into_owned();
    let dir_s = dir.to_string_lossy().into_owned();
    let uninst = format!("\"{}\" --uninstall", dir.join("uninstall.exe").display());
    let est_kb = (QUARRY_EXE.len() + WINDIVERT_DLL.len() + WINDIVERT_SYS.len()) / 1024;

    let entries: [(&str, &str, &str); 8] = [
        ("DisplayName", "REG_SZ", APP_NAME),
        ("DisplayVersion", "REG_SZ", APP_VERSION),
        ("Publisher", "REG_SZ", PUBLISHER),
        ("DisplayIcon", "REG_SZ", exe.as_str()),
        ("InstallLocation", "REG_SZ", dir_s.as_str()),
        ("UninstallString", "REG_SZ", uninst.as_str()),
        ("NoModify", "REG_DWORD", "1"),
        ("NoRepair", "REG_DWORD", "1"),
    ];
    for (name, ty, data) in entries {
        if !run_hidden(
            "reg",
            &["add", UNINSTALL_KEY, "/v", name, "/t", ty, "/d", data, "/f"],
        ) {
            return Err(format!("registro: falha ao gravar {name}"));
        }
    }
    let _ = run_hidden(
        "reg",
        &[
            "add",
            UNINSTALL_KEY,
            "/v",
            "EstimatedSize",
            "/t",
            "REG_DWORD",
            "/d",
            &est_kb.to_string(),
            "/f",
        ],
    );
    Ok(())
}

// =================== UNINSTALLER ===================

#[derive(Default)]
struct Uninstaller {
    done: bool,
    message: String,
}

impl eframe::App for Uninstaller {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                if !self.done {
                    ui.heading("Desinstalar o Quarry?");
                    ui.add_space(10.0);
                    ui.label("Isto remove o Quarry, os atalhos e o registro de desinstalação.");
                } else {
                    ui.heading("Quarry desinstalado");
                    ui.add_space(10.0);
                    ui.label(&self.message);
                }
            });
            ui.add_space(20.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !self.done {
                    if ui.button("Desinstalar").clicked() {
                        self.message = do_uninstall();
                        self.done = true;
                    }
                    if ui.button("Cancelar").clicked() {
                        std::process::exit(0);
                    }
                } else if ui.button("Fechar").clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        });
    }
}

fn do_uninstall() -> String {
    // a uninstall.exe está dentro da pasta de instalação
    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));

    // remove atalhos
    let sm = start_menu_dir();
    let _ = std::fs::remove_dir_all(&sm);
    let _ = std::fs::remove_file(public_desktop().join("Quarry.lnk"));

    // remove registro
    let _ = run_hidden("reg", &["delete", UNINSTALL_KEY, "/f"]);

    // agenda a remoção da pasta (não dá para apagar o exe em execução)
    if let Some(dir) = dir {
        let cmd = format!(
            "ping 127.0.0.1 -n 3 >nul & rmdir /s /q \"{}\"",
            dir.display()
        );
        let _ = Command::new("cmd")
            .args(["/c", &cmd])
            .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
            .spawn();
    }
    "Os arquivos serão removidos em instantes.".into()
}

// =================== helpers ===================

/// Roda um processo auxiliar com a janela oculta; devolve true se sucesso.
fn run_hidden(prog: &str, args: &[&str]) -> bool {
    Command::new(prog)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn env_path(var: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_default())
}

fn default_dir() -> PathBuf {
    env_path("ProgramFiles").join(APP_NAME)
}

fn start_menu_dir() -> PathBuf {
    env_path("ProgramData")
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join(APP_NAME)
}

fn public_desktop() -> PathBuf {
    let public = std::env::var("PUBLIC").unwrap_or_default();
    if public.is_empty() {
        env_path("USERPROFILE").join("Desktop")
    } else {
        PathBuf::from(public).join("Desktop")
    }
}
