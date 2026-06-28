//! Explorador de internals de um processo: mapa de memoria, threads, linha de
//! comando e extracao de strings. Read-only (nao escreve nada no alvo).
//!
//! As APIs `Nt*` (PEB, start address de thread) sao resolvidas por carregamento
//! dinamico do `ntdll.dll` — evita depender de features especificas do
//! windows-rs e mantem o build robusto.

use std::ffi::c_void;
use std::sync::OnceLock;

use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
use windows::Win32::System::ProcessStatus::GetMappedFileNameW;
use windows::Win32::System::Threading::{OpenThread, THREAD_QUERY_INFORMATION};

use crate::inject::{self, ModuleInfo};
use crate::memory;

// =================== mapa de memoria ===================

/// Uma regiao do espaco de enderecos do processo.
pub struct MemRegion {
    pub base: u64,
    pub size: u64,
    pub state: &'static str,
    pub protect: String,
    pub kind: &'static str,
    /// Arquivo mapeado (para regioes Image/Mapped) ou vazio.
    pub detail: String,
}

fn protect_str(p: u32) -> String {
    if p == 0 {
        return "-".into();
    }
    let base = match p & 0xFF {
        0x01 => "---",
        0x02 => "R--",
        0x04 => "RW-",
        0x08 => "RWc",
        0x10 => "--X",
        0x20 => "R-X",
        0x40 => "RWX",
        0x80 => "RcX",
        _ => "???",
    };
    let mut s = base.to_string();
    if p & 0x100 != 0 {
        s.push_str(" guard");
    }
    s
}

/// Enumera o mapa de memoria do processo via VirtualQueryEx.
pub fn memory_map(handle: HANDLE) -> Vec<MemRegion> {
    let mut out = Vec::new();
    let mut addr: usize = 0;
    for _ in 0..300_000 {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let n = unsafe {
            VirtualQueryEx(
                handle,
                Some(addr as *const c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if n == 0 {
            break;
        }
        let base = mbi.BaseAddress as u64;
        let size = mbi.RegionSize as u64;
        let state = match mbi.State.0 {
            0x1000 => "commit",
            0x2000 => "reserve",
            0x10000 => "free",
            _ => "?",
        };
        let kind = match mbi.Type.0 {
            0x100_0000 => "image",
            0x4_0000 => "mapped",
            0x2_0000 => "private",
            _ => "",
        };
        // nome do arquivo mapeado (so para image/mapped commitados)
        let mut detail = String::new();
        if mbi.State.0 == 0x1000 && (mbi.Type.0 == 0x100_0000 || mbi.Type.0 == 0x4_0000) {
            let mut buf = [0u16; 260];
            let len =
                unsafe { GetMappedFileNameW(handle, mbi.BaseAddress as *const c_void, &mut buf) };
            if len > 0 {
                let path = String::from_utf16_lossy(&buf[..len as usize]);
                detail = path.rsplit('\\').next().unwrap_or(&path).to_string();
            }
        }
        if mbi.State.0 != 0x10000 {
            out.push(MemRegion {
                base,
                size,
                state,
                protect: protect_str(mbi.Protect.0),
                kind,
                detail,
            });
        }
        let next = base.saturating_add(size) as usize;
        if next <= addr {
            break;
        }
        addr = next;
        if out.len() >= 50_000 {
            break;
        }
    }
    out
}

// =================== ntdll dinamico ===================

type NtQueryInformationProcessFn =
    unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;
type NtQueryInformationThreadFn =
    unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;

struct Ntdll {
    qip: Option<NtQueryInformationProcessFn>,
    qit: Option<NtQueryInformationThreadFn>,
}

fn ntdll() -> &'static Ntdll {
    static NT: OnceLock<Ntdll> = OnceLock::new();
    NT.get_or_init(|| unsafe {
        let module = GetModuleHandleW(windows::core::w!("ntdll.dll")).unwrap_or_default();
        let sym = |name: &[u8]| GetProcAddress(module, windows::core::PCSTR(name.as_ptr()));
        Ntdll {
            qip: sym(b"NtQueryInformationProcess\0").map(|f| std::mem::transmute(f)),
            qit: sym(b"NtQueryInformationThread\0").map(|f| std::mem::transmute(f)),
        }
    })
}

// =================== threads ===================

/// Uma thread do processo.
pub struct ThreadInfo {
    pub tid: u32,
    pub base_priority: i32,
    pub start: u64,
    /// "modulo.dll+0x1234" quando o start address cai num modulo conhecido.
    pub start_sym: String,
}

/// Enumera as threads do processo (TID, prioridade e start address resolvido).
pub fn threads(pid: u32, modules: &[ModuleInfo]) -> Vec<ThreadInfo> {
    let mut out = Vec::new();
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    let Ok(snap) = snap else {
        return out;
    };
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    unsafe {
        if Thread32First(snap, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    let start = thread_start(entry.th32ThreadID);
                    out.push(ThreadInfo {
                        tid: entry.th32ThreadID,
                        base_priority: entry.tpBasePri,
                        start,
                        start_sym: resolve(start, modules),
                    });
                }
                if Thread32Next(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

/// Win32 start address de uma thread (NtQueryInformationThread, classe 9).
fn thread_start(tid: u32) -> u64 {
    let Some(qit) = ntdll().qit else {
        return 0;
    };
    unsafe {
        let Ok(h) = OpenThread(THREAD_QUERY_INFORMATION, BOOL(0), tid) else {
            return 0;
        };
        let mut addr: u64 = 0;
        let mut ret = 0u32;
        // ThreadQuerySetWin32StartAddress = 9
        let status = qit(h, 9, &mut addr as *mut u64 as *mut c_void, 8, &mut ret);
        let _ = CloseHandle(h);
        if status == 0 {
            addr
        } else {
            0
        }
    }
}

/// Resolve um endereco para "modulo+offset" se cair num modulo carregado.
fn resolve(addr: u64, modules: &[ModuleInfo]) -> String {
    if addr == 0 {
        return String::new();
    }
    for m in modules {
        let end = m.base + m.size as u64;
        if addr >= m.base && addr < end {
            return format!("{}+0x{:X}", m.name, addr - m.base);
        }
    }
    String::new()
}

// =================== linha de comando (via PEB) ===================

/// Le a linha de comando do processo navegando o PEB (x64).
pub fn command_line(handle: HANDLE) -> Option<String> {
    let qip = ntdll().qip?;
    // PROCESS_BASIC_INFORMATION: PebBaseAddress fica no offset 8 (apos ExitStatus+pad).
    let mut pbi = [0u8; 48];
    let mut ret = 0u32;
    let status = unsafe {
        qip(
            handle,
            0, // ProcessBasicInformation
            pbi.as_mut_ptr() as *mut c_void,
            pbi.len() as u32,
            &mut ret,
        )
    };
    if status != 0 {
        return None;
    }
    let peb = u64::from_le_bytes(pbi[8..16].try_into().ok()?);
    if peb == 0 {
        return None;
    }
    // PEB.ProcessParameters @ +0x20 (x64)
    let pp = read_u64(handle, peb + 0x20)?;
    // RTL_USER_PROCESS_PARAMETERS.CommandLine (UNICODE_STRING) @ +0x70
    let len = memory::read_bytes(handle, pp + 0x70, 2).and_then(|b| {
        b.get(..2).map(|s| u16::from_le_bytes([s[0], s[1]]))
    })?;
    let buf_ptr = read_u64(handle, pp + 0x78)?;
    if len == 0 || buf_ptr == 0 {
        return None;
    }
    let raw = memory::read_bytes(handle, buf_ptr, len as usize)?;
    let utf16: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&utf16))
}

fn read_u64(handle: HANDLE, addr: u64) -> Option<u64> {
    let b = memory::read_bytes(handle, addr, 8)?;
    Some(u64::from_le_bytes(b.get(..8)?.try_into().ok()?))
}

// =================== modulos ===================

/// Lista os modulos carregados (reusa o enumerador da aba Injecao).
pub fn modules(pid: u32) -> Vec<ModuleInfo> {
    inject::list_modules(pid)
}

// =================== extracao de strings ===================

/// Uma string achada na memoria.
pub struct FoundString {
    pub addr: u64,
    pub wide: bool,
    pub text: String,
}

/// Varre as regioes legiveis e extrai strings ASCII e UTF-16 de no minimo
/// `min_len` caracteres imprimiveis. Limita o volume para nao travar a UI.
pub fn strings(handle: HANDLE, regions: &[MemRegion], min_len: usize) -> Vec<FoundString> {
    let mut out = Vec::new();
    // so regioes commitadas e legiveis (R no protect)
    for r in regions {
        if r.state != "commit" || !r.protect.starts_with('R') {
            continue;
        }
        // cap por regiao para nao ler centenas de MB
        let cap = (r.size as usize).min(8 * 1024 * 1024);
        let Some(buf) = memory::read_bytes(handle, r.base, cap) else {
            continue;
        };
        scan_ascii(&buf, r.base, min_len, &mut out);
        scan_utf16(&buf, r.base, min_len, &mut out);
        if out.len() >= 20_000 {
            break;
        }
    }
    out
}

fn printable(c: u8) -> bool {
    (0x20..=0x7E).contains(&c)
}

fn scan_ascii(buf: &[u8], base: u64, min_len: usize, out: &mut Vec<FoundString>) {
    let mut i = 0;
    while i < buf.len() {
        if printable(buf[i]) {
            let start = i;
            while i < buf.len() && printable(buf[i]) {
                i += 1;
            }
            if i - start >= min_len {
                out.push(FoundString {
                    addr: base + start as u64,
                    wide: false,
                    text: String::from_utf8_lossy(&buf[start..i]).into_owned(),
                });
                if out.len() >= 20_000 {
                    return;
                }
            }
        } else {
            i += 1;
        }
    }
}

fn scan_utf16(buf: &[u8], base: u64, min_len: usize, out: &mut Vec<FoundString>) {
    let mut i = 0;
    while i + 1 < buf.len() {
        // padrao UTF-16LE de ASCII: byte imprimivel seguido de 0x00
        if printable(buf[i]) && buf[i + 1] == 0 {
            let start = i;
            let mut s = String::new();
            while i + 1 < buf.len() && printable(buf[i]) && buf[i + 1] == 0 {
                s.push(buf[i] as char);
                i += 2;
            }
            if s.len() >= min_len {
                out.push(FoundString {
                    addr: base + start as u64,
                    wide: true,
                    text: s,
                });
                if out.len() >= 20_000 {
                    return;
                }
            }
        } else {
            i += 1;
        }
    }
}
