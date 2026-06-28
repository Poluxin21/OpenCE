//! Analisador estatico de PE (Portable Executable).
//!
//! Faz o parse de um `.exe`/`.dll` em disco (bytes crus) — cabecalhos, secoes
//! (com entropia), tabela de imports (IAT) e exports (EAT), deteccao de .NET e
//! heuristica de packer/compilador. Tudo bounds-checked: nunca entra em panico
//! com um arquivo malformado, so devolve `Err`/dados parciais.

/// Uma secao do PE.
pub struct PeSection {
    pub name: String,
    pub vaddr: u32,
    pub vsize: u32,
    pub raw_ptr: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    /// Entropia de Shannon (0..8) dos bytes crus — alta (>7) sugere compressao/cifra.
    pub entropy: f64,
}

impl PeSection {
    /// Flags legiveis (R/W/X/code/initialized…).
    pub fn flags(&self) -> String {
        let c = self.characteristics;
        let mut s = String::new();
        if c & 0x2000_0000 != 0 {
            s.push('X');
        }
        if c & 0x4000_0000 != 0 {
            s.push('R');
        }
        if c & 0x8000_0000 != 0 {
            s.push('W');
        }
        if c & 0x0000_0020 != 0 {
            s.push_str(" code");
        }
        if c & 0x0000_0040 != 0 {
            s.push_str(" data");
        }
        s
    }
}

/// Um modulo importado e as funcoes pedidas dele.
pub struct PeImport {
    pub dll: String,
    pub funcs: Vec<String>,
}

/// Uma funcao exportada.
pub struct PeExport {
    pub name: String,
    pub ordinal: u16,
    pub rva: u32,
}

/// Resultado completo da analise.
pub struct PeInfo {
    pub is_64: bool,
    pub machine_str: &'static str,
    pub timestamp: u32,
    pub subsystem_str: &'static str,
    pub entry_point: u32,
    pub image_base: u64,
    pub size_of_image: u32,
    pub dll_characteristics: u16,
    pub is_dll: bool,
    pub is_dotnet: bool,
    pub sections: Vec<PeSection>,
    pub imports: Vec<PeImport>,
    pub exports: Vec<PeExport>,
    /// Achados da heuristica (packer, alta entropia, .NET, etc.).
    pub verdict: Vec<String>,
}

impl PeInfo {
    /// Mitigacoes ligadas no header (DllCharacteristics): ASLR, DEP, CFG, etc.
    pub fn mitigations(&self) -> String {
        let d = self.dll_characteristics;
        let mut on = Vec::new();
        if d & 0x0040 != 0 {
            on.push("ASLR");
        }
        if d & 0x0020 != 0 {
            on.push("ASLR-alta-entropia");
        }
        if d & 0x0100 != 0 {
            on.push("DEP/NX");
        }
        if d & 0x4000 != 0 {
            on.push("CFG");
        }
        if d & 0x0400 != 0 {
            on.push("sem-SEH");
        }
        if d & 0x0080 != 0 {
            on.push("força-integridade");
        }
        if on.is_empty() {
            "(nenhuma)".into()
        } else {
            on.join(", ")
        }
    }
}

fn rd_u16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes(s.try_into().unwrap()))
}
fn rd_u32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}
fn rd_u64(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// Le uma string C (terminada em NUL) a partir de um offset de arquivo.
fn read_cstr(b: &[u8], off: usize, max: usize) -> String {
    let end = (off + max).min(b.len());
    let slice = b.get(off..end).unwrap_or(&[]);
    let n = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..n]).into_owned()
}

fn machine_name(m: u16) -> &'static str {
    match m {
        0x014c => "x86 (i386)",
        0x8664 => "x64 (AMD64)",
        0xAA64 => "ARM64",
        0x01c4 => "ARM (Thumb-2)",
        _ => "desconhecida",
    }
}

fn subsystem_name(s: u16) -> &'static str {
    match s {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows Console",
        5 => "OS/2 Console",
        7 => "POSIX Console",
        9 => "Windows CE GUI",
        10 => "EFI Application",
        _ => "outro",
    }
}

/// Entropia de Shannon (bits/byte) de um buffer.
fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Converte um RVA em offset de arquivo, usando a tabela de secoes.
fn rva_to_off(sections: &[PeSection], rva: u32) -> Option<usize> {
    for s in sections {
        if rva >= s.vaddr && rva < s.vaddr + s.vsize.max(s.raw_size) {
            return Some((rva - s.vaddr + s.raw_ptr) as usize);
        }
    }
    None
}

/// Analisa um PE a partir dos bytes do arquivo.
pub fn analyze(b: &[u8]) -> Result<PeInfo, String> {
    if b.len() < 0x40 || &b[0..2] != b"MZ" {
        return Err("não é um PE (assinatura MZ ausente)".into());
    }
    let e_lfanew = rd_u32(b, 0x3C).ok_or("e_lfanew inválido")? as usize;
    if b.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
        return Err("assinatura PE ausente".into());
    }

    // --- COFF File Header (logo após a assinatura PE de 4 bytes) ---
    let fh = e_lfanew + 4;
    let machine = rd_u16(b, fh).ok_or("header truncado")?;
    let num_sections = rd_u16(b, fh + 2).ok_or("header truncado")? as usize;
    let timestamp = rd_u32(b, fh + 4).unwrap_or(0);
    let opt_size = rd_u16(b, fh + 16).ok_or("header truncado")? as usize;
    let characteristics = rd_u16(b, fh + 18).unwrap_or(0);

    // --- Optional Header ---
    let oh = fh + 20;
    let magic = rd_u16(b, oh).ok_or("optional header ausente")?;
    let is_64 = magic == 0x20B;
    let entry_point = rd_u32(b, oh + 16).unwrap_or(0);
    let (image_base, dd_off, subsystem_off, dllchar_off) = if is_64 {
        (rd_u64(b, oh + 24).unwrap_or(0), oh + 112, oh + 68, oh + 70)
    } else {
        (rd_u32(b, oh + 28).unwrap_or(0) as u64, oh + 96, oh + 68, oh + 70)
    };
    let size_of_image = rd_u32(b, oh + 56).unwrap_or(0);
    let subsystem = rd_u16(b, subsystem_off).unwrap_or(0);
    let dll_characteristics = rd_u16(b, dllchar_off).unwrap_or(0);

    // data directories: [0]=export, [1]=import, [14]=COM/.NET
    let dd = |i: usize| -> (u32, u32) {
        let o = dd_off + i * 8;
        (rd_u32(b, o).unwrap_or(0), rd_u32(b, o + 4).unwrap_or(0))
    };
    let (export_rva, _) = dd(0);
    let (import_rva, _) = dd(1);
    let (com_rva, _) = dd(14);
    let is_dotnet = com_rva != 0;

    // --- Secoes (logo após o optional header) ---
    let sec_table = oh + opt_size;
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let s = sec_table + i * 40;
        let Some(name_raw) = b.get(s..s + 8) else { break };
        let name = {
            let n = name_raw.iter().position(|&c| c == 0).unwrap_or(8);
            String::from_utf8_lossy(&name_raw[..n]).into_owned()
        };
        let vsize = rd_u32(b, s + 8).unwrap_or(0);
        let vaddr = rd_u32(b, s + 12).unwrap_or(0);
        let raw_size = rd_u32(b, s + 16).unwrap_or(0);
        let raw_ptr = rd_u32(b, s + 20).unwrap_or(0);
        let characteristics = rd_u32(b, s + 36).unwrap_or(0);
        let ent = b
            .get(raw_ptr as usize..(raw_ptr as usize).saturating_add(raw_size as usize).min(b.len()))
            .map(entropy)
            .unwrap_or(0.0);
        sections.push(PeSection {
            name,
            vaddr,
            vsize,
            raw_ptr,
            raw_size,
            characteristics,
            entropy: ent,
        });
    }

    let imports = parse_imports(b, &sections, import_rva, is_64);
    let exports = parse_exports(b, &sections, export_rva);
    let is_dll = characteristics & 0x2000 != 0;

    let mut info = PeInfo {
        is_64,
        machine_str: machine_name(machine),
        timestamp,
        subsystem_str: subsystem_name(subsystem),
        entry_point,
        image_base,
        size_of_image,
        dll_characteristics,
        is_dll,
        is_dotnet,
        sections,
        imports,
        exports,
        verdict: Vec::new(),
    };
    info.verdict = build_verdict(&info);
    Ok(info)
}

fn parse_imports(b: &[u8], sections: &[PeSection], import_rva: u32, is_64: bool) -> Vec<PeImport> {
    let mut out = Vec::new();
    if import_rva == 0 {
        return out;
    }
    let Some(mut desc) = rva_to_off(sections, import_rva) else {
        return out;
    };
    // array de IMAGE_IMPORT_DESCRIPTOR (20 bytes), terminado por entrada zerada
    for _ in 0..1000 {
        let oft = rd_u32(b, desc).unwrap_or(0);
        let name_rva = rd_u32(b, desc + 12).unwrap_or(0);
        let first_thunk = rd_u32(b, desc + 16).unwrap_or(0);
        if name_rva == 0 && first_thunk == 0 {
            break;
        }
        let dll = rva_to_off(sections, name_rva)
            .map(|o| read_cstr(b, o, 256))
            .unwrap_or_default();

        let mut funcs = Vec::new();
        let thunk_rva = if oft != 0 { oft } else { first_thunk };
        if let Some(mut t) = rva_to_off(sections, thunk_rva) {
            for _ in 0..5000 {
                let (val, is_ord, next) = if is_64 {
                    let v = rd_u64(b, t).unwrap_or(0);
                    (v, v & 0x8000_0000_0000_0000 != 0, t + 8)
                } else {
                    let v = rd_u32(b, t).unwrap_or(0) as u64;
                    (v, v & 0x8000_0000 != 0, t + 4)
                };
                if val == 0 {
                    break;
                }
                if is_ord {
                    funcs.push(format!("#{}", val & 0xFFFF));
                } else if let Some(o) = rva_to_off(sections, (val & 0x7FFF_FFFF) as u32) {
                    // IMAGE_IMPORT_BY_NAME: Hint(2) + nome
                    funcs.push(read_cstr(b, o + 2, 256));
                }
                if funcs.len() >= 2000 {
                    break;
                }
                t = next;
            }
        }
        out.push(PeImport { dll, funcs });
        if out.len() >= 512 {
            break;
        }
        desc += 20;
    }
    out
}

fn parse_exports(b: &[u8], sections: &[PeSection], export_rva: u32) -> Vec<PeExport> {
    let mut out = Vec::new();
    if export_rva == 0 {
        return out;
    }
    let Some(ed) = rva_to_off(sections, export_rva) else {
        return out;
    };
    let base = rd_u32(b, ed + 16).unwrap_or(0);
    let num_funcs = rd_u32(b, ed + 20).unwrap_or(0) as usize;
    let num_names = rd_u32(b, ed + 24).unwrap_or(0) as usize;
    let addr_funcs = rd_u32(b, ed + 28).unwrap_or(0);
    let addr_names = rd_u32(b, ed + 32).unwrap_or(0);
    let addr_ords = rd_u32(b, ed + 36).unwrap_or(0);

    let (Some(of_funcs), Some(of_names), Some(of_ords)) = (
        rva_to_off(sections, addr_funcs),
        rva_to_off(sections, addr_names),
        rva_to_off(sections, addr_ords),
    ) else {
        return out;
    };

    for i in 0..num_names.min(num_funcs).min(20_000) {
        let name_rva = rd_u32(b, of_names + i * 4).unwrap_or(0);
        let ord = rd_u16(b, of_ords + i * 2).unwrap_or(0);
        let func_rva = rd_u32(b, of_funcs + ord as usize * 4).unwrap_or(0);
        let name = rva_to_off(sections, name_rva)
            .map(|o| read_cstr(b, o, 256))
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        out.push(PeExport {
            name,
            ordinal: ord.wrapping_add(base as u16),
            rva: func_rva,
        });
    }
    out
}

/// Heuristicas: packer, alta entropia, .NET, poucos imports, etc.
fn build_verdict(info: &PeInfo) -> Vec<String> {
    let mut v = Vec::new();

    if info.is_dotnet {
        v.push("Binário .NET / gerenciado (CLR).".into());
    }

    // entropia alta
    let hi: Vec<&PeSection> = info.sections.iter().filter(|s| s.entropy > 7.2).collect();
    if !hi.is_empty() {
        let names: Vec<&str> = hi.iter().map(|s| s.name.as_str()).collect();
        v.push(format!(
            "Seção(ões) de alta entropia ({}) — provável compressão/cifra (packer).",
            names.join(", ")
        ));
    }

    // nomes de secao conhecidos de packers
    for s in &info.sections {
        let n = s.name.to_ascii_uppercase();
        if n.contains("UPX") {
            v.push("Seções UPX — empacotado com UPX.".into());
            break;
        }
    }

    // secao virtual >> raw (descompacta em runtime)
    if info
        .sections
        .iter()
        .any(|s| s.raw_size == 0 && s.vsize > 0x1000)
    {
        v.push("Seção sem dados crus (vsize ≫ raw) — código descomprimido em runtime.".into());
    }

    // poucos imports
    let total_funcs: usize = info.imports.iter().map(|i| i.funcs.len()).sum();
    if info.imports.len() <= 2 && total_funcs < 10 && !info.is_dotnet {
        v.push(format!(
            "IAT minúscula ({} DLL/{} funções) — típico de packer/protector.",
            info.imports.len(),
            total_funcs
        ));
    }

    // compilador (heuristica leve por nomes de secao)
    let secs: Vec<String> = info.sections.iter().map(|s| s.name.to_lowercase()).collect();
    if secs.iter().any(|n| n == ".text") && secs.iter().any(|n| n == ".rdata") {
        v.push("Layout típico de MSVC (.text/.rdata/.data).".into());
    } else if secs.iter().any(|n| n.contains("rodata") || n == ".eh_frame") {
        v.push("Layout típico de GCC/MinGW.".into());
    }

    if v.is_empty() {
        v.push("Nada de anormal — provável binário não-empacotado.".into());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe() {
        assert!(analyze(b"not a pe at all, just text padding padding").is_err());
    }

    #[test]
    fn parses_kernel32() {
        // Valida contra um PE real do sistema. Pula se nao existir (CI atipico).
        let Ok(bytes) = std::fs::read(r"C:\Windows\System32\kernel32.dll") else {
            return;
        };
        let info = analyze(&bytes).expect("kernel32 deve parsear");
        assert!(info.is_64, "kernel32 x64");
        assert!(info.is_dll);
        assert!(!info.sections.is_empty());
        assert!(info.sections.iter().any(|s| s.name == ".text"));
        // kernel32 exporta milhares de funcoes, entre elas CreateFileW
        assert!(info.exports.iter().any(|e| e.name == "CreateFileW"));
        // e importa de ntdll/api-ms
        assert!(!info.imports.is_empty());
    }
}
