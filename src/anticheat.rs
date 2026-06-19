//! Deteccao de anticheat. `detect()` classifica o alvo em KernelAc/UsermodeAc/
//! Unprotected combinando tres sinais: drivers `.sys` no kernel, modulos
//! carregados no processo, e o nome do executavel. A GUI usa o resultado para
//! bloquear injecao quando ha AC kernel e rotear para a secao correta.

use std::ffi::c_void;

use windows::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverBaseNameW};

use crate::inject::ModuleInfo;

/// Resultado da classificacao de um processo alvo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Protection {
    /// Anticheat kernel detectado. Injecao deve ser BLOQUEADA.
    KernelAc(String),
    /// Anticheat user-mode/hibrido detectado. Injecao sob confirmacao.
    UsermodeAc(String),
    /// Nenhuma protecao conhecida. Injecao liberada.
    Unprotected,
}

impl Protection {
    /// True quando a injecao de codigo deve ficar bloqueada (AC kernel).
    pub fn blocks_injection(&self) -> bool {
        matches!(self, Protection::KernelAc(_))
    }

    /// Nome do anticheat detectado, se houver.
    pub fn ac_name(&self) -> Option<&str> {
        match self {
            Protection::KernelAc(n) | Protection::UsermodeAc(n) => Some(n),
            Protection::Unprotected => None,
        }
    }
}

/// Detalhe da classificacao, com os motivos (para exibir na GUI/log).
#[derive(Clone, Debug)]
pub struct Detection {
    pub protection: Protection,
    /// Drivers de anticheat encontrados no kernel (base names).
    pub reasons: Vec<String>,
}

/// Assinatura de anticheat: driver kernel (`.sys`) -> nome do produto.
/// Comparacao em minusculas.
const KERNEL_AC_DRIVERS: &[(&str, &str)] = &[
    ("vgk.sys", "Riot Vanguard"),
    ("easyanticheat.sys", "Easy Anti-Cheat"),
    ("easyanticheat_eos.sys", "Easy Anti-Cheat (EOS)"),
    ("bedaisy.sys", "BattlEye"),
    ("faceit.sys", "FACEIT AC"),
    ("mhyprot2.sys", "miHoYo Protect"),
    ("mhyprot3.sys", "miHoYo Protect"),
    ("ntiolib.sys", "nProtect GameGuard"),
    ("aksdf.sys", "nProtect GameGuard"),
];

/// Assinatura de anticheat user-mode: modulo (`.dll`) -> nome do produto.
const USERMODE_AC_MODULES: &[(&str, &str)] = &[
    ("easyanticheat.dll", "Easy Anti-Cheat"),
    ("easyanticheat_x64.dll", "Easy Anti-Cheat"),
    ("beclient.dll", "BattlEye"),
    ("beclient_x64.dll", "BattlEye"),
    ("gameguard", "nProtect GameGuard"),
];

/// Banco de assinaturas por executavel -> anticheat kernel esperado.
/// Fallback quando o driver ainda nao subiu (ex.: AC inicia depois do attach).
const GAME_KERNEL_AC: &[(&str, &str)] = &[
    ("valorant-win64-shipping.exe", "Riot Vanguard"),
    ("league of legends.exe", "Riot Vanguard"),
    ("fortniteclient-win64-shipping.exe", "Easy Anti-Cheat / BattlEye"),
    ("r5apex.exe", "Easy Anti-Cheat"),
    ("rainbowsix.exe", "BattlEye"),
    ("destiny2.exe", "BattlEye"),
    ("genshinimpact.exe", "miHoYo Protect"),
];

/// Enumera os drivers carregados no kernel e devolve os base names em
/// minusculas (ex.: "vgk.sys", "ntoskrnl.exe"). Read-only, nao toca alvo.
pub fn loaded_driver_names() -> Vec<String> {
    let mut names = Vec::new();
    unsafe {
        // 1a chamada: descobrir quantos bytes sao necessarios.
        let mut needed: u32 = 0;
        if EnumDeviceDrivers(std::ptr::null_mut(), 0, &mut needed).is_err() || needed == 0 {
            return names;
        }
        let count = needed as usize / std::mem::size_of::<*mut c_void>();
        let mut bases: Vec<*mut c_void> = vec![std::ptr::null_mut(); count];
        let cb = (bases.len() * std::mem::size_of::<*mut c_void>()) as u32;
        if EnumDeviceDrivers(bases.as_mut_ptr(), cb, &mut needed).is_err() {
            return names;
        }
        let mut buf = [0u16; 260];
        for &base in &bases {
            if base.is_null() {
                continue;
            }
            let len = GetDeviceDriverBaseNameW(base, &mut buf);
            if len > 0 {
                let name = String::from_utf16_lossy(&buf[..len as usize]);
                names.push(name.to_lowercase());
            }
        }
    }
    names
}

/// Classifica o alvo combinando drivers kernel, modulos e o nome do exe.
///
/// `modules` deve vir de [`crate::inject::list_modules`]; `exe_name` e o
/// nome do executavel do processo (ex.: "VALORANT-Win64-Shipping.exe").
pub fn detect(exe_name: &str, modules: &[ModuleInfo]) -> Detection {
    let mut reasons = Vec::new();

    // --- Sinal 1: drivers kernel carregados (definitivo) ---
    let drivers = loaded_driver_names();
    for (sig, product) in KERNEL_AC_DRIVERS {
        if drivers.iter().any(|d| d == sig) {
            reasons.push(format!("driver kernel '{sig}' presente"));
            return Detection {
                protection: Protection::KernelAc((*product).to_string()),
                reasons,
            };
        }
    }

    // --- Sinal 3 (fallback): assinatura por nome de exe ---
    // Avaliado antes do sinal 2 porque, se o jogo e conhecidamente protegido
    // por AC kernel, tratamos como kernel mesmo que o driver ainda nao tenha
    // subido (ex.: anexado durante o boot do jogo).
    let exe_lower = exe_name.to_lowercase();
    for (game, product) in GAME_KERNEL_AC {
        if exe_lower == *game {
            reasons.push(format!(
                "executavel '{game}' usa AC kernel conhecido (driver ainda nao detectado)"
            ));
            return Detection {
                protection: Protection::KernelAc((*product).to_string()),
                reasons,
            };
        }
    }

    // --- Sinal 2: modulos user-mode dentro do alvo ---
    for m in modules {
        let name = m.name.to_lowercase();
        for (sig, product) in USERMODE_AC_MODULES {
            if name.contains(sig) {
                reasons.push(format!("modulo '{}' carregado no processo", m.name));
                return Detection {
                    protection: Protection::UsermodeAc((*product).to_string()),
                    reasons,
                };
            }
        }
    }

    Detection {
        protection: Protection::Unprotected,
        reasons,
    }
}
