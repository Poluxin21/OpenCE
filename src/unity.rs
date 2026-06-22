//! Dissector de jogos Unity / Mono / IL2CPP (read-only).
//!
//! Detecta o backend de scripting do alvo a partir dos modulos carregados e,
//! para Mono, lê a tabela de exports do PE **direto da memoria do processo**
//! (sem executar nada dentro do alvo) para confirmar e listar a API
//! `mono_*` — os pontos de entrada que um dissector mais profundo usaria
//! (`mono_get_root_domain`, `mono_assembly_foreach`, `mono_class_*`...).
//!
//! É um ponto de partida seguro: identifica o motor e o caminho a seguir.
//! Caminhar os metadados (assemblies → classes → campos) exige chamar essas
//! funcoes no alvo (CreateRemoteThread) — detectável — e fica para uma fase
//! futura; por isso aqui ficamos só na leitura.

use windows::Win32::Foundation::HANDLE;

use crate::inject::ModuleInfo;
use crate::memory;

/// Backend de scripting detectado.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Engine {
    /// Mono (DLL mono / mono-2.0-bdwgc) — metadados acessíveis via API mono_*.
    Mono,
    /// IL2CPP (GameAssembly.dll) — código AOT; precisa de dump de metadata.
    Il2Cpp,
    /// Unity sem backend de script identificado (só UnityPlayer.dll).
    Unity,
    /// Não parece Unity.
    None,
}

impl Engine {
    pub fn label(&self) -> &'static str {
        match self {
            Engine::Mono => "Unity (Mono)",
            Engine::Il2Cpp => "Unity (IL2CPP)",
            Engine::Unity => "Unity (backend desconhecido)",
            Engine::None => "Não-Unity",
        }
    }
}

/// Resultado da análise do alvo.
pub struct UnityInfo {
    pub engine: Engine,
    pub mono_module: Option<ModuleInfo>,
    pub game_assembly: Option<ModuleInfo>,
    pub unity_player: Option<ModuleInfo>,
    /// Total de exports `mono_*` encontrados na DLL do Mono.
    pub mono_export_count: usize,
    /// Amostra dos exports `mono_*` (até [`SAMPLE_LIMIT`]).
    pub mono_exports: Vec<String>,
}

/// Quantos nomes de export guardar para exibir.
pub const SAMPLE_LIMIT: usize = 60;

/// Nomes (em minúsculas) das DLLs do runtime Mono.
fn is_mono_dll(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "mono.dll" || n.starts_with("mono-2.0") || (n.starts_with("mono") && n.ends_with(".dll"))
}

/// Analisa os módulos do alvo e, se for Mono, lê os exports da DLL.
pub fn analyze(handle: HANDLE, modules: &[ModuleInfo]) -> UnityInfo {
    let find = |pred: &dyn Fn(&str) -> bool| modules.iter().find(|m| pred(&m.name)).cloned();

    let mono_module = find(&|n| is_mono_dll(n));
    let game_assembly = find(&|n| n.eq_ignore_ascii_case("GameAssembly.dll"));
    let unity_player = find(&|n| n.eq_ignore_ascii_case("UnityPlayer.dll"));

    let engine = if mono_module.is_some() {
        Engine::Mono
    } else if game_assembly.is_some() {
        Engine::Il2Cpp
    } else if unity_player.is_some() {
        Engine::Unity
    } else {
        Engine::None
    };

    let mut mono_exports = Vec::new();
    let mut mono_export_count = 0;
    if let Some(m) = &mono_module {
        let names = read_pe_exports(handle, m.base);
        for n in names {
            if n.starts_with("mono_") {
                mono_export_count += 1;
                if mono_exports.len() < SAMPLE_LIMIT {
                    mono_exports.push(n);
                }
            }
        }
    }

    UnityInfo {
        engine,
        mono_module,
        game_assembly,
        unity_player,
        mono_export_count,
        mono_exports,
    }
}

/// Lê a tabela de nomes de export de um módulo PE carregado em `base` no
/// processo `handle`. Suporta PE32 e PE32+. Retorna os nomes exportados.
fn read_pe_exports(handle: HANDLE, base: u64) -> Vec<String> {
    let mut out = Vec::new();
    // --- cabeçalho DOS: 'MZ' + e_lfanew em 0x3C ---
    let Some(dos) = memory::read_bytes(handle, base, 0x40) else {
        return out;
    };
    if dos.len() < 0x40 || &dos[0..2] != b"MZ" {
        return out;
    }
    let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().unwrap()) as u64;

    // --- cabeçalhos NT: assinatura 'PE\0\0' + FILE_HEADER (20) + OPTIONAL ---
    let Some(nt) = memory::read_bytes(handle, base + e_lfanew, 0x18) else {
        return out;
    };
    if nt.len() < 0x18 || &nt[0..4] != b"PE\0\0" {
        return out;
    }
    // OPTIONAL_HEADER começa em e_lfanew + 4 (sig) + 20 (FILE_HEADER).
    let opt = base + e_lfanew + 24;
    // Magic: 0x10B = PE32, 0x20B = PE32+. As data directories ficam em offset
    // 96 (PE32) ou 112 (PE32+) dentro do optional header; export dir = índice 0.
    let Some(magic_b) = memory::read_bytes(handle, opt, 2) else {
        return out;
    };
    let magic = u16::from_le_bytes([magic_b[0], magic_b[1]]);
    let dd_off = if magic == 0x20B { 112 } else { 96 };
    let Some(dir) = memory::read_bytes(handle, opt + dd_off, 8) else {
        return out;
    };
    let export_rva = u32::from_le_bytes(dir[0..4].try_into().unwrap()) as u64;
    if export_rva == 0 {
        return out;
    }

    // --- IMAGE_EXPORT_DIRECTORY (40 bytes) ---
    let Some(ed) = memory::read_bytes(handle, base + export_rva, 40) else {
        return out;
    };
    let number_of_names = u32::from_le_bytes(ed[0x18..0x1C].try_into().unwrap()) as usize;
    let addr_of_names_rva = u32::from_le_bytes(ed[0x20..0x24].try_into().unwrap()) as u64;
    if number_of_names == 0 || addr_of_names_rva == 0 {
        return out;
    }
    let number_of_names = number_of_names.min(20_000); // sanidade

    // array de RVAs de nomes (u32 cada)
    let Some(name_rvas) = memory::read_bytes(handle, base + addr_of_names_rva, number_of_names * 4)
    else {
        return out;
    };
    for chunk in name_rvas.chunks_exact(4) {
        let rva = u32::from_le_bytes(chunk.try_into().unwrap()) as u64;
        if rva == 0 {
            continue;
        }
        if let Some(name) = read_c_string(handle, base + rva, 128) {
            out.push(name);
        }
    }
    out
}

/// Lê uma string C (terminada em NUL) de até `max` bytes.
fn read_c_string(handle: HANDLE, addr: u64, max: usize) -> Option<String> {
    let bytes = memory::read_bytes(handle, addr, max)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}
