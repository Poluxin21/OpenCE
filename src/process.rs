//! Enumeracao e abertura de processos (Windows).

use windows::core::Result;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

/// Informacao basica de um processo listado.
#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

/// Lista todos os processos visiveis no sistema.
pub fn list_processes() -> Vec<ProcessInfo> {
    let mut out = Vec::new();
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return out,
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );
                out.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    name,
                });
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

/// Um processo aberto com permissoes de leitura/escrita de memoria.
/// Fecha o handle automaticamente no Drop.
pub struct OpenProcessHandle {
    pub pid: u32,
    pub handle: HANDLE,
}

impl OpenProcessHandle {
    pub fn open(pid: u32) -> Result<Self> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
                    | PROCESS_QUERY_INFORMATION,
                false,
                pid,
            )?
        };
        Ok(Self { pid, handle })
    }

    pub fn raw(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for OpenProcessHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

// SAFETY: HANDLE is an opaque OS pointer; sharing it across threads for
// ReadProcessMemory/WriteProcessMemory is safe.
unsafe impl Send for OpenProcessHandle {}
unsafe impl Sync for OpenProcessHandle {}
