//! Auto Assembler: interpreta scripts estilo Cheat Engine para criar
//! code caves, escanear AOB, alocar memoria e aplicar/desfazer patches.
//!
//! Comandos suportados (uma instrucao por linha; `//` inicia comentario):
//! Numeros (convencao Cheat Engine): sem prefixo = hex, `0x..`/`$..` = hex,
//! `#..` = decimal, `(float)N`/`(double)N` = bits IEEE-754.
//!
//!   aobscanmodule(simbolo, modulo, AA BB ?? CC)
//!   aobscan(simbolo, AA BB ?? CC)
//!   alloc(simbolo, tamanho[, perto_de])
//!   label(nome)                              (declaracao opcional)
//!   registersymbol(nome) / unregistersymbol(nome)
//!   dealloc(simbolo)
//!   nome:                                    ancora; se for endereco conhecido move o cursor,
//!                                            senao define um label no endereco atual
//!   db AA BB CC                              escreve bytes crus
//!   dd <expr> / dq <expr>                    escreve 4/8 bytes (little-endian)
//!   nop [n]                                  escreve n bytes 0x90 (1 se omitido)
//!   jmp <alvo> / call <alvo>                 salto/chamada relativo (rel32)
//!   je/jne/jg/jl/jge/jle/ja/jb/...  <alvo>   salto condicional near (rel32)
//!   jmp64 <alvo>                             salto absoluto x64 (FF 25 + endereco)
//!   <instrucao x86>                          mov/add/sub/cmp/lea/push/... (ver asm_x86)
//!
//! `<expr>` aceita `simbolo`, numero, ou `simbolo+0x10` / `endereco-8`.
//! Linhas que nao casam com os comandos acima sao montadas como instrucao
//! x86-64 pelo modulo `asm_x86` (ex: `mov [rbx+0x10], eax`).

use std::collections::HashMap;
use std::ffi::c_void;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};

use crate::asm_x86;
use crate::inject::{self, ModuleInfo};
use crate::memory::{self, Region};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Enable,
    Disable,
}

/// Estado persistente entre Enable e Disable (simbolos e alocacoes).
pub struct AsmState {
    pub symbols: HashMap<String, u64>,
    pub allocs: Vec<(String, u64, usize)>,
}

impl AsmState {
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
            allocs: Vec::new(),
        }
    }
}

enum Emit {
    Db(Vec<u8>),
    Nop(usize),
    JmpRel(String),
    CallRel(String),
    JmpAbs(String),
    /// salto condicional near (0F 8x rel32); guarda o codigo de condicao e o alvo.
    Jcc(u8, String),
    Dq(String),
    Dd(String),
    Insn(asm_x86::Insn),
}

/// Codigo de condicao (nibble do opcode 0F 8x) para um mnemonico de salto
/// condicional, cobrindo os sinonimos comuns. None se nao for um Jcc.
fn cc_code(mnem: &str) -> Option<u8> {
    Some(match mnem {
        "jo" => 0x0,
        "jno" => 0x1,
        "jb" | "jc" | "jnae" => 0x2,
        "jae" | "jnb" | "jnc" => 0x3,
        "je" | "jz" => 0x4,
        "jne" | "jnz" => 0x5,
        "jbe" | "jna" => 0x6,
        "ja" | "jnbe" => 0x7,
        "js" => 0x8,
        "jns" => 0x9,
        "jp" | "jpe" => 0xA,
        "jnp" | "jpo" => 0xB,
        "jl" | "jnge" => 0xC,
        "jge" | "jnl" => 0xD,
        "jle" | "jng" => 0xE,
        "jg" | "jnle" => 0xF,
        _ => return None,
    })
}

impl Emit {
    fn size(&self) -> usize {
        match self {
            Emit::Db(b) => b.len(),
            Emit::Nop(n) => *n,
            Emit::JmpRel(_) | Emit::CallRel(_) => 5,
            Emit::Jcc(_, _) => 6, // 0F 8x + rel32
            Emit::JmpAbs(_) => 14,
            Emit::Dq(_) => 8,
            Emit::Dd(_) => 4,
            Emit::Insn(i) => i.size(),
        }
    }

    fn resolve(&self, symbols: &HashMap<String, u64>, addr: u64) -> Result<Vec<u8>, String> {
        Ok(match self {
            Emit::Db(b) => b.clone(),
            Emit::Nop(n) => vec![0x90; *n],
            Emit::JmpRel(t) => rel_branch(0xE9, parse_expr(symbols, t)?, addr)?,
            Emit::CallRel(t) => rel_branch(0xE8, parse_expr(symbols, t)?, addr)?,
            Emit::Jcc(cc, t) => {
                let target = parse_expr(symbols, t)?;
                // rel32 medido a partir do fim da instrucao (6 bytes: 0F 8x + rel32)
                let rel = target as i64 - (addr as i64 + 6);
                if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
                    return Err(format!(
                        "salto condicional fora do alcance rel32 ({rel:#X}); aproxime o cave"
                    ));
                }
                let mut v = vec![0x0F, 0x80 | cc];
                v.extend_from_slice(&(rel as i32).to_le_bytes());
                v
            }
            Emit::JmpAbs(t) => {
                let target = parse_expr(symbols, t)?;
                let mut v = vec![0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
                v.extend_from_slice(&target.to_le_bytes());
                v
            }
            Emit::Dq(t) => parse_expr(symbols, t)?.to_le_bytes().to_vec(),
            Emit::Dd(t) => (parse_expr(symbols, t)? as u32).to_le_bytes().to_vec(),
            Emit::Insn(i) => {
                let imm = match i.imm_text() {
                    Some(t) => parse_expr(symbols, t)?,
                    None => 0,
                };
                i.build(imm as i64)?
            }
        })
    }
}

fn rel_branch(opcode: u8, target: u64, addr: u64) -> Result<Vec<u8>, String> {
    let rel = target as i64 - (addr as i64 + 5);
    if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
        return Err(format!(
            "salto fora do alcance rel32 ({rel:#X}); use jmp64 ou aloque o cave mais perto"
        ));
    }
    let mut v = vec![opcode];
    v.extend_from_slice(&(rel as i32).to_le_bytes());
    Ok(v)
}

enum Item {
    Anchor(String),
    Emit(Emit),
}

enum Defer {
    Dealloc(String),
    Unregister(String),
}

/// Compara/remove um prefixo ignorando maiusculas/minusculas.
fn strip_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Convencao de numero estilo Cheat Engine (igual a de `asm_x86`):
///   `(float)N`/`(double)N` -> bits IEEE-754 (32/64 bits)
///   `#N` = decimal, `$N`/`0xN` = hex, `N` = hex (sem prefixo = hex)
fn parse_num(tok: &str) -> Option<u64> {
    let t = tok.trim();
    if let Some(inner) = strip_ci(t, "(float)") {
        return Some(inner.trim().parse::<f32>().ok()?.to_bits() as u64);
    }
    if let Some(inner) = strip_ci(t, "(double)") {
        return Some(inner.trim().parse::<f64>().ok()?.to_bits());
    }
    if let Some(d) = t.strip_prefix('#') {
        d.parse::<u64>().ok()
    } else if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if let Some(h) = t.strip_prefix('$') {
        u64::from_str_radix(h, 16).ok()
    } else {
        u64::from_str_radix(t, 16).ok()
    }
}

fn parse_operand(symbols: &HashMap<String, u64>, tok: &str) -> Result<u64, String> {
    let t = tok.trim();
    // Simbolo antes de numero: com numero-hex-por-padrao, labels como `face`/`dead`
    // seriam interpretados como hex se a busca de simbolo nao viesse primeiro.
    if let Some(v) = symbols.get(t) {
        Ok(*v)
    } else if let Some(n) = parse_num(t) {
        Ok(n)
    } else {
        Err(format!("simbolo desconhecido: '{t}'"))
    }
}

fn parse_expr(symbols: &HashMap<String, u64>, s: &str) -> Result<u64, String> {
    let s = s.trim();
    // `(float)-1.0` contem um '-' que nao e um operador da expressao.
    if strip_ci(s, "(float)").is_some() || strip_ci(s, "(double)").is_some() {
        return parse_operand(symbols, s);
    }
    for (i, ch) in s.char_indices() {
        if i > 0 && (ch == '+' || ch == '-') {
            let a = parse_operand(symbols, &s[..i])?;
            let b = parse_operand(symbols, &s[i + 1..])?;
            return Ok(if ch == '+' {
                a.wrapping_add(b)
            } else {
                a.wrapping_sub(b)
            });
        }
    }
    parse_operand(symbols, s)
}

fn parse_call(line: &str) -> Option<(String, Vec<String>)> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    if close < open {
        return None;
    }
    let name = line[..open].trim().to_lowercase();
    let args = line[open + 1..close]
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    Some((name, args))
}

fn module_range(modules: &[ModuleInfo], name: &str) -> Option<(u64, u64)> {
    modules
        .iter()
        .find(|m| m.name.eq_ignore_ascii_case(name))
        .map(|m| (m.base, m.base + m.size as u64))
}

fn aob_in_module(
    handle: HANDLE,
    regions: &[Region],
    modules: &[ModuleInfo],
    name: &str,
    pat: &[Option<u8>],
) -> Option<u64> {
    let (base, end) = module_range(modules, name)?;
    let mod_regions: Vec<Region> = regions
        .iter()
        .copied()
        .filter(|r| r.base >= base && r.base < end)
        .collect();
    inject::aob_scan(handle, &mod_regions, pat, 1).into_iter().next()
}

/// Aloca memoria executavel, preferindo um endereco proximo de `near` para que
/// saltos rel32 alcancem (necessario em x64). Faz uma varredura por paginas livres.
fn alloc_near(handle: HANDLE, size: usize, near: u64) -> Option<u64> {
    if near != 0 {
        let gran: u64 = 0x10000;
        let start = near & !(gran - 1);
        for i in 0..0x8000u64 {
            for cand in [start.wrapping_sub(i * gran), start.wrapping_add(i * gran)] {
                if cand == 0 {
                    continue;
                }
                let p = unsafe {
                    VirtualAllocEx(
                        handle,
                        Some(cand as *const c_void),
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    )
                };
                if !p.is_null() {
                    return Some(p as u64);
                }
            }
        }
    }
    inject::alloc(handle, size)
}

/// Extrai as linhas de uma secao ([ENABLE] ou [DISABLE]).
fn section_lines(script: &str, section: Section) -> Vec<String> {
    let want = match section {
        Section::Enable => "[enable]",
        Section::Disable => "[disable]",
    };
    let mut out = Vec::new();
    let mut active = false;
    for raw in script.lines() {
        let line = match raw.find("//") {
            Some(i) => &raw[..i],
            None => raw,
        }
        .trim();
        if line.is_empty() {
            continue;
        }
        let low = line.to_lowercase();
        if low == "[enable]" || low == "[disable]" {
            active = low == want;
            continue;
        }
        if active {
            out.push(line.to_string());
        }
    }
    out
}

/// Executa uma secao do script. Retorna o log em caso de sucesso.
pub fn run_section(
    handle: HANDLE,
    pid: u32,
    script: &str,
    section: Section,
    state: &mut AsmState,
) -> Result<Vec<String>, String> {
    let lines = section_lines(script, section);
    if lines.is_empty() {
        return Ok(vec!["(secao vazia)".into()]);
    }

    let mut log = Vec::new();
    let modules = inject::list_modules(pid);
    let mut regions: Option<Vec<Region>> = None;

    let mut items: Vec<Item> = Vec::new();
    let mut deferred: Vec<Defer> = Vec::new();

    // Passo 1: executa comandos e coleta ancoras/emissoes.
    for line in &lines {
        if line.ends_with(':') {
            items.push(Item::Anchor(line[..line.len() - 1].trim().to_string()));
            continue;
        }

        if let Some((cmd, args)) = parse_call(line) {
            match cmd.as_str() {
                "alloc" => {
                    let name = args.first().ok_or("alloc: faltam argumentos")?.clone();
                    let size = args
                        .get(1)
                        .and_then(|a| parse_num(a))
                        .ok_or("alloc: tamanho invalido")? as usize;
                    let near = match args.get(2) {
                        Some(a) => parse_expr(&state.symbols, a)?,
                        None => 0,
                    };
                    let addr = alloc_near(handle, size, near)
                        .ok_or("alloc: VirtualAllocEx falhou")?;
                    state.symbols.insert(name.clone(), addr);
                    state.allocs.push((name.clone(), addr, size));
                    log.push(format!("alloc {name} = {addr:016X} ({size} bytes)"));
                }
                "aobscanmodule" => {
                    let name = args.first().ok_or("aobscanmodule: faltam argumentos")?.clone();
                    let module = args.get(1).ok_or("aobscanmodule: falta o modulo")?;
                    let pat = inject::parse_aob(args.get(2).map(|s| s.as_str()).unwrap_or(""))
                        .ok_or("aobscanmodule: padrao AOB invalido")?;
                    let regs = regions.get_or_insert_with(|| memory::enumerate_regions(handle));
                    let addr = aob_in_module(handle, regs, &modules, module, &pat).ok_or(
                        format!("aobscanmodule: padrao nao encontrado em {module}"),
                    )?;
                    state.symbols.insert(name.clone(), addr);
                    log.push(format!("aobscanmodule {name} = {addr:016X}"));
                }
                "aobscan" => {
                    let name = args.first().ok_or("aobscan: faltam argumentos")?.clone();
                    let pat = inject::parse_aob(args.get(1).map(|s| s.as_str()).unwrap_or(""))
                        .ok_or("aobscan: padrao AOB invalido")?;
                    let regs = regions.get_or_insert_with(|| memory::enumerate_regions(handle));
                    let addr = inject::aob_scan(handle, regs, &pat, 1)
                        .into_iter()
                        .next()
                        .ok_or("aobscan: padrao nao encontrado")?;
                    state.symbols.insert(name.clone(), addr);
                    log.push(format!("aobscan {name} = {addr:016X}"));
                }
                "label" => { /* declaracao opcional; o label e definido pela ancora `nome:` */ }
                "registersymbol" => { /* simbolos ja persistem no AsmState */ }
                "unregistersymbol" => {
                    if let Some(name) = args.first() {
                        deferred.push(Defer::Unregister(name.clone()));
                    }
                }
                "dealloc" => {
                    if let Some(name) = args.first() {
                        deferred.push(Defer::Dealloc(name.clone()));
                    }
                }
                other => return Err(format!("comando desconhecido: {other}")),
            }
            continue;
        }

        // linha de emissao (db/dd/dq/nop/jmp/call/jmp64)
        let mut toks = line.split_whitespace();
        let head = toks.next().unwrap_or("").to_lowercase();
        let rest: Vec<&str> = toks.collect();
        let emit = match head.as_str() {
            "db" => {
                let mut bytes = Vec::new();
                for t in &rest {
                    bytes.push(
                        u8::from_str_radix(t, 16).map_err(|_| format!("db: byte invalido '{t}'"))?,
                    );
                }
                Emit::Db(bytes)
            }
            "nop" => {
                let n = rest.first().and_then(|t| parse_num(t)).unwrap_or(1) as usize;
                Emit::Nop(n.max(1))
            }
            "jmp" => Emit::JmpRel(rest.join("")),
            "call" => Emit::CallRel(rest.join("")),
            "jmp64" => Emit::JmpAbs(rest.join("")),
            _ if cc_code(&head).is_some() => {
                Emit::Jcc(cc_code(&head).unwrap(), rest.join(""))
            }
            "dq" => Emit::Dq(rest.join("")),
            "dd" => Emit::Dd(rest.join("")),
            _ => match asm_x86::parse(line) {
                Some(res) => Emit::Insn(res?),
                None => {
                    return Err(format!(
                        "instrucao nao suportada: '{head}' (use db para bytes crus)"
                    ))
                }
            },
        };
        items.push(Item::Emit(emit));
    }

    // Passo 2: layout — atribui enderecos as ancoras e emissoes.
    let mut placed: Vec<(u64, Emit)> = Vec::new();
    let mut cursor: Option<u64> = None;
    for item in items {
        match item {
            Item::Anchor(name) => {
                if let Some(&a) = state.symbols.get(&name) {
                    cursor = Some(a);
                } else {
                    let c = cursor.ok_or(format!(
                        "label '{name}:' antes de um local de escrita (use newmem: ou o ponto de injecao)"
                    ))?;
                    state.symbols.insert(name, c);
                }
            }
            Item::Emit(e) => {
                let c = cursor
                    .ok_or("instrucao antes de definir onde escrever (falta uma ancora `nome:`)")?;
                let sz = e.size();
                placed.push((c, e));
                cursor = Some(c + sz as u64);
            }
        }
    }

    // Passo 3: resolve simbolos e escreve na memoria.
    for (addr, e) in &placed {
        let bytes = e.resolve(&state.symbols, *addr)?;
        if !inject::write_code(handle, *addr, &bytes) {
            return Err(format!("falha ao escrever {} bytes em {addr:016X}", bytes.len()));
        }
        log.push(format!("escrito {} bytes em {addr:016X}", bytes.len()));
    }

    // Passo 4: dealloc / unregister.
    for d in deferred {
        match d {
            Defer::Dealloc(name) => {
                if let Some(pos) = state.allocs.iter().position(|(n, _, _)| *n == name) {
                    let (_, addr, _) = state.allocs.remove(pos);
                    inject::free(handle, addr);
                    state.symbols.remove(&name);
                    log.push(format!("dealloc {name} ({addr:016X})"));
                }
            }
            Defer::Unregister(name) => {
                state.symbols.remove(&name);
            }
        }
    }

    Ok(log)
}
