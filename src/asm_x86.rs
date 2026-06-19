//! Montador (encoder) de um subconjunto pratico de x86-64, suficiente para
//! escrever code caves legiveis no Auto Assembler em vez de `db` cru.
//!
//! Instrucoes suportadas (operandos de 32 ou 64 bits):
//!   mov   reg,imm | reg,reg | reg,[mem] | [mem],reg | [mem],imm
//!   add/sub/and/or/xor/cmp/adc/sbb   reg,imm | reg,reg | reg,[mem] | [mem],reg | [mem],imm
//!   test  reg,reg | reg,imm | reg,[mem] | [mem],reg
//!   lea   reg,[mem]
//!   inc/dec/neg/not   reg | [mem]
//!   push/pop  reg
//!   ret
//!   SSE: movss/movsd/movups/movupd/movaps/movapd  xmm,xmm/[mem] | [mem],xmm
//!        add/sub/mul/div ss|sd|ps|pd   xmm,xmm/[mem]
//!        xorps/xorpd, cvtsi2ss/cvtsi2sd, cvttss2si/cvttsd2si
//!        movd/movq   xmm,reg/[mem] | reg/[mem],xmm | movq xmm,xmm
//!
//! Memoria: [base], [base+disp], [base-disp], [base+index*escala+disp]
//! (escala 1/2/4/8). Numeros (convencao Cheat Engine): sem prefixo = hex,
//! `0x..`/`$..` = hex, `#..` = decimal, `(float)N`/`(double)N` = bits IEEE-754.
//! Imediatos podem ser um simbolo do script (resolvido na hora da escrita);
//! por isso `parse` guarda o texto do imediato e `build` recebe o valor.

/// Registrador de proposito geral (somente 32 ou 64 bits neste subconjunto).
#[derive(Clone, Copy)]
pub struct GReg {
    num: u8,  // 0..15
    size: u8, // 4 ou 8
}

/// Operando de memoria: base + index*escala + deslocamento.
#[derive(Clone)]
struct Mem {
    base: u8,
    index: Option<u8>,
    scale: u8,
    disp: i64,
}

/// Destino de ModRM: um registrador ou um endereco de memoria.
#[derive(Clone)]
enum Rm {
    Reg(u8),
    Mem(Mem),
}

/// Forma normalizada da instrucao, com tamanho ja deterministico.
enum Repr {
    /// opcode unico com ModRM.reg = `reg` e r/m = `rm` (mov/add/lea/test/...).
    RmR { opcode: u8, w: bool, reg: u8, rm: Rm },
    /// opcode + /digit em ModRM.reg, seguido de imediato de `imm_width` bytes
    /// (0 = sem imediato; usado tambem por inc/dec/neg/not).
    RmI {
        opcode: u8,
        digit: u8,
        w: bool,
        rm: Rm,
        imm_width: u8,
    },
    /// mov reg, imm  (B8+rd; imediato de 4 ou 8 bytes conforme o tamanho).
    MovRI { reg: GReg },
    /// Instrucao SSE de dois bytes de opcode: [prefixo legado] [REX] 0F opcode ModRM.
    /// `reg` e `rm` carregam registradores xmm (ou GP, no caso de movd/movq).
    Sse {
        prefix: Option<u8>,
        opcode: u8,
        w: bool,
        reg: u8,
        rm: Rm,
    },
    Push { num: u8 },
    Pop { num: u8 },
    Ret,
}

/// Uma instrucao montada: a forma + o texto do imediato (se houver).
pub struct Insn {
    repr: Repr,
    imm: Option<String>,
}

impl Insn {
    /// Texto do imediato a resolver (simbolo ou numero), se a instrucao tiver.
    pub fn imm_text(&self) -> Option<&str> {
        self.imm.as_deref()
    }

    /// Tamanho em bytes — independe do valor do imediato (largura fixa).
    pub fn size(&self) -> usize {
        self.build(0).map(|v| v.len()).unwrap_or(0)
    }

    /// Monta os bytes finais. `imm` e o valor ja resolvido do imediato.
    pub fn build(&self, imm: i64) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        match &self.repr {
            Repr::RmR { opcode, w, reg, rm } => emit_rm(*w, *reg, rm, *opcode, &mut out)?,
            Repr::RmI {
                opcode,
                digit,
                w,
                rm,
                imm_width,
            } => {
                emit_rm(*w, *digit, rm, *opcode, &mut out)?;
                append_imm(imm, *imm_width, &mut out)?;
            }
            Repr::MovRI { reg } => {
                push_rex(reg.size == 8, 0, 0, reg.num >> 3, &mut out);
                out.push(0xB8 + (reg.num & 7));
                if reg.size == 8 {
                    out.extend_from_slice(&(imm as u64).to_le_bytes());
                } else {
                    append_imm(imm, 4, &mut out)?;
                }
            }
            Repr::Sse { prefix, opcode, w, reg, rm } => {
                emit_sse(*prefix, *w, *opcode, *reg, rm, &mut out)?
            }
            Repr::Push { num } => {
                if *num >= 8 {
                    out.push(0x41); // REX.B
                }
                out.push(0x50 + (num & 7));
            }
            Repr::Pop { num } => {
                if *num >= 8 {
                    out.push(0x41);
                }
                out.push(0x58 + (num & 7));
            }
            Repr::Ret => out.push(0xC3),
        }
        Ok(out)
    }
}

/// Emite REX se algum bit for necessario (sem suporte a registradores de 8 bits).
fn push_rex(w: bool, r: u8, x: u8, b: u8, out: &mut Vec<u8>) {
    if w || r != 0 || x != 0 || b != 0 {
        out.push(0x40 | ((w as u8) << 3) | ((r & 1) << 2) | ((x & 1) << 1) | (b & 1));
    }
}

/// Emite REX + opcode + ModRM (+ SIB + disp) para um par (reg, r/m).
fn emit_rm(w: bool, reg: u8, rm: &Rm, opcode: u8, out: &mut Vec<u8>) -> Result<(), String> {
    match rm {
        Rm::Reg(rnum) => {
            push_rex(w, reg >> 3, 0, rnum >> 3, out);
            out.push(opcode);
            out.push(0xC0 | ((reg & 7) << 3) | (rnum & 7));
        }
        Rm::Mem(m) => {
            let (sib, disp, rex_x, rex_b, mod_bits, rm_field) = encode_mem(m)?;
            push_rex(w, reg >> 3, rex_x, rex_b, out);
            out.push(opcode);
            out.push((mod_bits << 6) | ((reg & 7) << 3) | rm_field);
            if let Some(s) = sib {
                out.push(s);
            }
            out.extend_from_slice(&disp);
        }
    }
    Ok(())
}

/// Emite uma instrucao SSE: prefixo legado (66/F2/F3) -> REX -> 0F -> opcode -> ModRM.
/// A ordem importa: o prefixo legado vem antes do REX, e o 0F faz parte do opcode.
fn emit_sse(
    prefix: Option<u8>,
    w: bool,
    opcode: u8,
    reg: u8,
    rm: &Rm,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    if let Some(p) = prefix {
        out.push(p);
    }
    match rm {
        Rm::Reg(rnum) => {
            push_rex(w, reg >> 3, 0, rnum >> 3, out);
            out.push(0x0F);
            out.push(opcode);
            out.push(0xC0 | ((reg & 7) << 3) | (rnum & 7));
        }
        Rm::Mem(m) => {
            let (sib, disp, rex_x, rex_b, mod_bits, rm_field) = encode_mem(m)?;
            push_rex(w, reg >> 3, rex_x, rex_b, out);
            out.push(0x0F);
            out.push(opcode);
            out.push((mod_bits << 6) | ((reg & 7) << 3) | rm_field);
            if let Some(s) = sib {
                out.push(s);
            }
            out.extend_from_slice(&disp);
        }
    }
    Ok(())
}

/// Calcula SIB/disp/mod/rm e os bits REX.X/REX.B para um operando de memoria.
fn encode_mem(m: &Mem) -> Result<(Option<u8>, Vec<u8>, u8, u8, u8, u8), String> {
    let base_low = m.base & 7;
    let rex_b = (m.base >> 3) & 1;
    // rsp/r12 (base_low==4) exigem SIB; idem se houver indice.
    let need_sib = m.index.is_some() || base_low == 4;

    // Selecao do modo de enderecamento (disp0/disp8/disp32). rbp/r13 (base_low==5)
    // nao admitem disp0, entao forcamos disp8 = 0.
    let (mod_bits, disp): (u8, Vec<u8>) = if m.disp == 0 && base_low != 5 {
        (0, vec![])
    } else if (-128..=127).contains(&m.disp) {
        (1, vec![m.disp as i8 as u8])
    } else {
        if m.disp < i32::MIN as i64 || m.disp > i32::MAX as i64 {
            return Err(format!("deslocamento fora do alcance: {:#X}", m.disp));
        }
        (2, (m.disp as i32).to_le_bytes().to_vec())
    };

    if need_sib {
        let (index_field, rex_x) = match m.index {
            Some(i) => {
                if i & 7 == 4 {
                    return Err("rsp/esp nao pode ser registrador de indice".into());
                }
                (i & 7, (i >> 3) & 1)
            }
            None => (4, 0), // 100 = sem indice
        };
        let scale_bits = match m.scale {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => return Err(format!("escala invalida: {}", m.scale)),
        };
        let sib = (scale_bits << 6) | (index_field << 3) | base_low;
        Ok((Some(sib), disp, rex_x, rex_b, mod_bits, 4))
    } else {
        Ok((None, disp, 0, rex_b, mod_bits, base_low))
    }
}

/// Anexa um imediato de `width` bytes (4 ou 8), validando o alcance para 4.
fn append_imm(imm: i64, width: u8, out: &mut Vec<u8>) -> Result<(), String> {
    match width {
        0 => {}
        4 => {
            if imm < i32::MIN as i64 || imm > u32::MAX as i64 {
                return Err(format!("imediato {imm:#X} nao cabe em 32 bits"));
            }
            out.extend_from_slice(&(imm as u32).to_le_bytes());
        }
        8 => out.extend_from_slice(&(imm as u64).to_le_bytes()),
        _ => return Err(format!("largura de imediato invalida: {width}")),
    }
    Ok(())
}

// ----------------------------- Parsing -----------------------------

/// Compara/remove um prefixo ignorando maiusculas/minusculas.
fn strip_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Convencao de numero estilo Cheat Engine:
///   `(float)N`  -> bits IEEE-754 de 32 bits (4 bytes)
///   `(double)N` -> bits IEEE-754 de 64 bits (8 bytes)
///   `#N`        -> decimal
///   `$N`/`0xN`  -> hexadecimal
///   `N`         -> hexadecimal (sem prefixo = hex, como no CE)
fn parse_num(tok: &str) -> Option<i64> {
    let t = tok.trim();
    if let Some(inner) = strip_ci(t, "(float)") {
        return Some(inner.trim().parse::<f32>().ok()?.to_bits() as i64);
    }
    if let Some(inner) = strip_ci(t, "(double)") {
        return Some(inner.trim().parse::<f64>().ok()?.to_bits() as i64);
    }
    let (neg, t) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t),
    };
    let v = if let Some(d) = t.strip_prefix('#') {
        d.parse::<i64>().ok()?
    } else if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()?
    } else if let Some(h) = t.strip_prefix('$') {
        i64::from_str_radix(h, 16).ok()?
    } else {
        i64::from_str_radix(t, 16).ok()?
    };
    Some(if neg { -v } else { v })
}

fn parse_reg(tok: &str) -> Option<GReg> {
    let t = tok.trim().to_lowercase();
    const R64: [&str; 16] = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];
    const R32: [&str; 16] = [
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
        "r12d", "r13d", "r14d", "r15d",
    ];
    if let Some(i) = R64.iter().position(|r| *r == t) {
        return Some(GReg { num: i as u8, size: 8 });
    }
    if let Some(i) = R32.iter().position(|r| *r == t) {
        return Some(GReg { num: i as u8, size: 4 });
    }
    None
}

/// Reconhece um registrador SSE xmm0..xmm15. Retorna o numero (0..15).
fn parse_xmm(tok: &str) -> Option<u8> {
    let t = tok.trim().to_lowercase();
    let n = t.strip_prefix("xmm")?;
    let num: u8 = n.parse().ok()?;
    if num <= 15 {
        Some(num)
    } else {
        None
    }
}

/// Mapeia uma palavra de tamanho ("dword"/"qword") para 4/8 bytes.
fn size_keyword(tok: &str) -> Option<u8> {
    match tok.to_lowercase().as_str() {
        "byte" => Some(1),
        "word" => Some(2),
        "dword" => Some(4),
        "qword" => Some(8),
        _ => None,
    }
}

/// Operando ja classificado.
enum Operand {
    Reg(GReg),
    Xmm(u8),
    Mem(Mem, Option<u8>), // tamanho explicito, se houver palavra-chave
    Imm(String),
}

fn parse_mem(inner: &str) -> Result<Mem, String> {
    // remove colchetes e espacos internos
    let inner: String = inner
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if inner.is_empty() {
        return Err("operando de memoria vazio".into());
    }
    // separa termos preservando o sinal: troca '-' por '+-'
    let normalized = inner.replace('-', "+-");
    let normalized = normalized.trim_start_matches('+');

    let mut base: Option<u8> = None;
    let mut index: Option<u8> = None;
    let mut scale: u8 = 1;
    let mut disp: i64 = 0;

    for (i, term) in normalized.split('+').enumerate() {
        if term.is_empty() {
            continue;
        }
        if let Some((a, b)) = term.split_once('*') {
            // index*escala (em qualquer ordem)
            let (reg_tok, scale_tok) = if parse_reg(a).is_some() { (a, b) } else { (b, a) };
            let r = parse_reg(reg_tok).ok_or_else(|| format!("indice invalido: '{term}'"))?;
            scale = parse_num(scale_tok).ok_or_else(|| format!("escala invalida: '{term}'"))? as u8;
            index = Some(r.num);
        } else if let Some(r) = parse_reg(term) {
            if i == 0 || base.is_none() {
                base = Some(r.num);
            } else {
                index = Some(r.num);
            }
        } else if let Some(n) = parse_num(term) {
            disp = disp.wrapping_add(n);
        } else {
            return Err(format!("termo de memoria invalido: '{term}'"));
        }
    }

    let base = base.ok_or("operando de memoria sem registrador base")?;
    Ok(Mem { base, index, scale, disp })
}

fn parse_operand(s: &str) -> Result<Operand, String> {
    let s = s.trim();
    // palavra de tamanho opcional antes de [..]
    let (size, rest) = match s.split_once(char::is_whitespace) {
        Some((kw, rest)) if size_keyword(kw).is_some() => (size_keyword(kw), rest.trim()),
        _ => (None, s),
    };
    if rest.starts_with('[') {
        return Ok(Operand::Mem(parse_mem(rest)?, size));
    }
    if let Some(x) = parse_xmm(rest) {
        return Ok(Operand::Xmm(x));
    }
    if let Some(r) = parse_reg(rest) {
        return Ok(Operand::Reg(r));
    }
    Ok(Operand::Imm(rest.to_string()))
}

/// Tabela ALU: (opcode "r/m,r", digito do grupo 0x81/0x83).
/// O opcode "r,r/m" e sempre o "r/m,r" + 2.
fn alu(mnem: &str) -> Option<(u8, u8)> {
    Some(match mnem {
        "add" => (0x01, 0),
        "or" => (0x09, 1),
        "adc" => (0x11, 2),
        "sbb" => (0x19, 3),
        "and" => (0x21, 4),
        "sub" => (0x29, 5),
        "xor" => (0x31, 6),
        "cmp" => (0x39, 7),
        _ => return None,
    })
}

/// Tenta interpretar uma linha como instrucao x86. Retorna:
///   None        -> o mnemonico nao e conhecido (o chamador trata o erro)
///   Some(Ok)    -> instrucao montada
///   Some(Err)   -> mnemonico conhecido, mas operandos invalidos
pub fn parse(line: &str) -> Option<Result<Insn, String>> {
    let line = line.trim();
    let (mnem, rest) = match line.split_once(char::is_whitespace) {
        Some((m, r)) => (m.to_lowercase(), r.trim()),
        None => (line.to_lowercase(), ""),
    };

    let ops_res: Result<Vec<Operand>, String> = if rest.is_empty() {
        Ok(Vec::new())
    } else {
        rest.split(',').map(|p| parse_operand(p)).collect()
    };

    match mnem.as_str() {
        "ret" => Some(Ok(Insn { repr: Repr::Ret, imm: None })),
        "mov" => Some(parse_mov(ops_res)),
        "lea" => Some(parse_lea(ops_res)),
        "test" => Some(parse_test(ops_res)),
        "push" | "pop" => Some(parse_pushpop(&mnem, ops_res)),
        "inc" | "dec" | "neg" | "not" => Some(parse_unary(&mnem, ops_res)),
        "movd" | "movq" => Some(parse_movdq(&mnem, ops_res)),
        m if sse_table(m).is_some() => Some(parse_sse(m, ops_res)),
        m if alu(m).is_some() => Some(parse_alu(m, ops_res)),
        _ => None,
    }
}

/// Tabela SSE: mnemonico -> (prefixo legado, opcode "carrega" xmm<-r/m,
/// opcode "armazena" r/m<-xmm). As aritmeticas so tem forma de carga (store=None).
fn sse_table(mnem: &str) -> Option<(Option<u8>, u8, Option<u8>)> {
    Some(match mnem {
        // moves escalares/empacotados
        "movss" => (Some(0xF3), 0x10, Some(0x11)),
        "movsd" => (Some(0xF2), 0x10, Some(0x11)),
        "movups" => (None, 0x10, Some(0x11)),
        "movupd" => (Some(0x66), 0x10, Some(0x11)),
        "movaps" => (None, 0x28, Some(0x29)),
        "movapd" => (Some(0x66), 0x28, Some(0x29)),
        // aritmetica escalar (single)
        "addss" => (Some(0xF3), 0x58, None),
        "subss" => (Some(0xF3), 0x5C, None),
        "mulss" => (Some(0xF3), 0x59, None),
        "divss" => (Some(0xF3), 0x5E, None),
        // aritmetica escalar (double)
        "addsd" => (Some(0xF2), 0x58, None),
        "subsd" => (Some(0xF2), 0x5C, None),
        "mulsd" => (Some(0xF2), 0x59, None),
        "divsd" => (Some(0xF2), 0x5E, None),
        // aritmetica empacotada (single/double)
        "addps" => (None, 0x58, None),
        "subps" => (None, 0x5C, None),
        "mulps" => (None, 0x59, None),
        "divps" => (None, 0x5E, None),
        "addpd" => (Some(0x66), 0x58, None),
        "subpd" => (Some(0x66), 0x5C, None),
        "mulpd" => (Some(0x66), 0x59, None),
        "divpd" => (Some(0x66), 0x5E, None),
        // conversoes/xorps comuns em code caves
        "xorps" => (None, 0x57, None),
        "xorpd" => (Some(0x66), 0x57, None),
        "cvtsi2ss" => (Some(0xF3), 0x2A, None),
        "cvtsi2sd" => (Some(0xF2), 0x2A, None),
        "cvttss2si" => (Some(0xF3), 0x2C, None),
        "cvttsd2si" => (Some(0xF2), 0x2C, None),
        _ => return None,
    })
}

/// Monta uma instrucao SSE generica (dst xmm, src xmm/mem) e a forma de store
/// (mem, xmm) quando existe. cvtsi2ss/cvtsi2sd recebem GP como origem.
fn parse_sse(mnem: &str, ops: Result<Vec<Operand>, String>) -> Result<Insn, String> {
    let (prefix, load, store) = sse_table(mnem).unwrap();
    let (a, b) = two_ops(ops, mnem)?;
    let mk = |reg: u8, rm: Rm, opcode: u8, w: bool| Insn {
        repr: Repr::Sse { prefix, opcode, w, reg, rm },
        imm: None,
    };
    match (a, b) {
        (Operand::Xmm(d), Operand::Xmm(s)) => Ok(mk(d, Rm::Reg(s), load, false)),
        (Operand::Xmm(d), Operand::Mem(m, _)) => Ok(mk(d, Rm::Mem(m), load, false)),
        // cvtsi2ss/cvtsi2sd xmm, r/m32|64
        (Operand::Xmm(d), Operand::Reg(s)) if mnem.starts_with("cvtsi2") => {
            Ok(mk(d, Rm::Reg(s.num), load, s.size == 8))
        }
        // cvttss2si/cvttsd2si r32|64, xmm/m
        (Operand::Reg(d), Operand::Xmm(s)) if mnem.starts_with("cvtt") => {
            Ok(mk(d.num, Rm::Reg(s), load, d.size == 8))
        }
        (Operand::Reg(d), Operand::Mem(m, _)) if mnem.starts_with("cvtt") => {
            Ok(mk(d.num, Rm::Mem(m), load, d.size == 8))
        }
        (Operand::Mem(m, _), Operand::Xmm(s)) => {
            let op = store.ok_or_else(|| format!("{mnem}: nao tem forma de store em memoria"))?;
            Ok(mk(s, Rm::Mem(m), op, false))
        }
        _ => Err(format!("{mnem}: combinacao de operandos invalida")),
    }
}

/// movd/movq entre xmm e GP/memoria (e movq xmm,xmm via F3 0F 7E).
fn parse_movdq(mnem: &str, ops: Result<Vec<Operand>, String>) -> Result<Insn, String> {
    let q = mnem == "movq";
    let (a, b) = two_ops(ops, mnem)?;
    let sse = |prefix, opcode, w, reg, rm| Insn {
        repr: Repr::Sse { prefix: Some(prefix), opcode, w, reg, rm },
        imm: None,
    };
    match (a, b) {
        // xmm <- gp/mem : 66 0F 6E  (REX.W para movq)
        (Operand::Xmm(d), Operand::Reg(s)) => Ok(sse(0x66, 0x6E, s.size == 8, d, Rm::Reg(s.num))),
        (Operand::Xmm(d), Operand::Mem(m, _)) => Ok(sse(0x66, 0x6E, q, d, Rm::Mem(m))),
        // gp/mem <- xmm : 66 0F 7E
        (Operand::Reg(d), Operand::Xmm(s)) => Ok(sse(0x66, 0x7E, d.size == 8, s, Rm::Reg(d.num))),
        (Operand::Mem(m, _), Operand::Xmm(s)) => Ok(sse(0x66, 0x7E, q, s, Rm::Mem(m))),
        // movq xmm, xmm/m : F3 0F 7E (apenas movq)
        (Operand::Xmm(d), Operand::Xmm(s)) if q => Ok(sse(0xF3, 0x7E, false, d, Rm::Reg(s))),
        _ => Err(format!("{mnem}: combinacao de operandos invalida")),
    }
}

fn two_ops(ops: Result<Vec<Operand>, String>, mnem: &str) -> Result<(Operand, Operand), String> {
    let mut ops = ops?;
    if ops.len() != 2 {
        return Err(format!("{mnem}: esperados 2 operandos"));
    }
    let b = ops.pop().unwrap();
    let a = ops.pop().unwrap();
    Ok((a, b))
}

fn rm_size(opsize: Option<u8>, default: u8) -> Result<bool, String> {
    match opsize.unwrap_or(default) {
        4 => Ok(false),
        8 => Ok(true),
        n => Err(format!("tamanho de {n} bytes nao suportado (use dword/qword)")),
    }
}

fn parse_mov(ops: Result<Vec<Operand>, String>) -> Result<Insn, String> {
    let (a, b) = two_ops(ops, "mov")?;
    match (a, b) {
        (Operand::Reg(dst), Operand::Imm(t)) => Ok(Insn {
            repr: Repr::MovRI { reg: dst },
            imm: Some(t),
        }),
        (Operand::Reg(dst), Operand::Reg(src)) => {
            check_same_size(dst, src, "mov")?;
            Ok(Insn {
                repr: Repr::RmR { opcode: 0x89, w: dst.size == 8, reg: src.num, rm: Rm::Reg(dst.num) },
                imm: None,
            })
        }
        (Operand::Reg(dst), Operand::Mem(m, _)) => Ok(Insn {
            repr: Repr::RmR { opcode: 0x8B, w: dst.size == 8, reg: dst.num, rm: Rm::Mem(m) },
            imm: None,
        }),
        (Operand::Mem(m, _), Operand::Reg(src)) => Ok(Insn {
            repr: Repr::RmR { opcode: 0x89, w: src.size == 8, reg: src.num, rm: Rm::Mem(m) },
            imm: None,
        }),
        (Operand::Mem(m, sz), Operand::Imm(t)) => Ok(Insn {
            repr: Repr::RmI {
                opcode: 0xC7,
                digit: 0,
                w: rm_size(sz, 4)?,
                rm: Rm::Mem(m),
                imm_width: 4,
            },
            imm: Some(t),
        }),
        _ => Err("mov: combinacao de operandos invalida".into()),
    }
}

fn parse_alu(mnem: &str, ops: Result<Vec<Operand>, String>) -> Result<Insn, String> {
    let (rmr, digit) = alu(mnem).unwrap();
    let (a, b) = two_ops(ops, mnem)?;
    match (a, b) {
        (Operand::Reg(dst), Operand::Imm(t)) => Ok(Insn {
            repr: Repr::RmI {
                opcode: 0x81,
                digit,
                w: dst.size == 8,
                rm: Rm::Reg(dst.num),
                imm_width: 4,
            },
            imm: Some(t),
        }),
        (Operand::Mem(m, sz), Operand::Imm(t)) => Ok(Insn {
            repr: Repr::RmI {
                opcode: 0x81,
                digit,
                w: rm_size(sz, 4)?,
                rm: Rm::Mem(m),
                imm_width: 4,
            },
            imm: Some(t),
        }),
        (Operand::Reg(dst), Operand::Reg(src)) => {
            check_same_size(dst, src, mnem)?;
            Ok(Insn {
                repr: Repr::RmR { opcode: rmr, w: dst.size == 8, reg: src.num, rm: Rm::Reg(dst.num) },
                imm: None,
            })
        }
        (Operand::Reg(dst), Operand::Mem(m, _)) => Ok(Insn {
            repr: Repr::RmR { opcode: rmr + 2, w: dst.size == 8, reg: dst.num, rm: Rm::Mem(m) },
            imm: None,
        }),
        (Operand::Mem(m, _), Operand::Reg(src)) => Ok(Insn {
            repr: Repr::RmR { opcode: rmr, w: src.size == 8, reg: src.num, rm: Rm::Mem(m) },
            imm: None,
        }),
        _ => Err(format!("{mnem}: combinacao de operandos invalida")),
    }
}

fn parse_test(ops: Result<Vec<Operand>, String>) -> Result<Insn, String> {
    let (a, b) = two_ops(ops, "test")?;
    match (a, b) {
        (Operand::Reg(dst), Operand::Imm(t)) => Ok(Insn {
            repr: Repr::RmI {
                opcode: 0xF7,
                digit: 0,
                w: dst.size == 8,
                rm: Rm::Reg(dst.num),
                imm_width: 4,
            },
            imm: Some(t),
        }),
        (Operand::Mem(m, sz), Operand::Imm(t)) => Ok(Insn {
            repr: Repr::RmI {
                opcode: 0xF7,
                digit: 0,
                w: rm_size(sz, 4)?,
                rm: Rm::Mem(m),
                imm_width: 4,
            },
            imm: Some(t),
        }),
        (Operand::Reg(dst), Operand::Reg(src)) => {
            check_same_size(dst, src, "test")?;
            Ok(Insn {
                repr: Repr::RmR { opcode: 0x85, w: dst.size == 8, reg: src.num, rm: Rm::Reg(dst.num) },
                imm: None,
            })
        }
        (Operand::Reg(r), Operand::Mem(m, _)) | (Operand::Mem(m, _), Operand::Reg(r)) => Ok(Insn {
            repr: Repr::RmR { opcode: 0x85, w: r.size == 8, reg: r.num, rm: Rm::Mem(m) },
            imm: None,
        }),
        _ => Err("test: combinacao de operandos invalida".into()),
    }
}

fn parse_lea(ops: Result<Vec<Operand>, String>) -> Result<Insn, String> {
    let (a, b) = two_ops(ops, "lea")?;
    match (a, b) {
        (Operand::Reg(dst), Operand::Mem(m, _)) => Ok(Insn {
            repr: Repr::RmR { opcode: 0x8D, w: dst.size == 8, reg: dst.num, rm: Rm::Mem(m) },
            imm: None,
        }),
        _ => Err("lea: use 'lea reg, [mem]'".into()),
    }
}

fn parse_unary(mnem: &str, ops: Result<Vec<Operand>, String>) -> Result<Insn, String> {
    let mut ops = ops?;
    if ops.len() != 1 {
        return Err(format!("{mnem}: esperado 1 operando"));
    }
    // inc=0xFF/0, dec=0xFF/1, not=0xF7/2, neg=0xF7/3
    let (opcode, digit) = match mnem {
        "inc" => (0xFF, 0),
        "dec" => (0xFF, 1),
        "not" => (0xF7, 2),
        "neg" => (0xF7, 3),
        _ => unreachable!(),
    };
    let (rm, w) = match ops.pop().unwrap() {
        Operand::Reg(r) => (Rm::Reg(r.num), r.size == 8),
        Operand::Mem(m, sz) => (Rm::Mem(m), rm_size(sz, 4)?),
        _ => return Err(format!("{mnem}: operando deve ser registrador ou memoria")),
    };
    Ok(Insn {
        repr: Repr::RmI { opcode, digit, w, rm, imm_width: 0 },
        imm: None,
    })
}

fn parse_pushpop(mnem: &str, ops: Result<Vec<Operand>, String>) -> Result<Insn, String> {
    let mut ops = ops?;
    if ops.len() != 1 {
        return Err(format!("{mnem}: esperado 1 operando"));
    }
    match ops.pop().unwrap() {
        Operand::Reg(r) => {
            if r.size != 8 {
                return Err(format!("{mnem}: use um registrador de 64 bits (rax, rbx, ...)"));
            }
            let repr = if mnem == "push" {
                Repr::Push { num: r.num }
            } else {
                Repr::Pop { num: r.num }
            };
            Ok(Insn { repr, imm: None })
        }
        _ => Err(format!("{mnem}: operando deve ser um registrador")),
    }
}

fn check_same_size(a: GReg, b: GReg, mnem: &str) -> Result<(), String> {
    if a.size != b.size {
        return Err(format!("{mnem}: tamanhos de registrador diferentes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asm(line: &str) -> Vec<u8> {
        let insn = parse(line).expect("mnemonico conhecido").expect("operandos validos");
        let imm = insn.imm_text().and_then(parse_num).unwrap_or(0);
        insn.build(imm).expect("montagem")
    }

    #[test]
    fn mov_reg_imm() {
        // sem prefixo = hex (convencao Cheat Engine)
        assert_eq!(asm("mov eax, 3E7"), vec![0xB8, 0xE7, 0x03, 0x00, 0x00]);
        // '#' forca decimal: #999 == 0x3E7
        assert_eq!(asm("mov eax, #999"), vec![0xB8, 0xE7, 0x03, 0x00, 0x00]);
        // mov rax, imm64
        assert_eq!(
            asm("mov rax, 0x1122334455667788"),
            vec![0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
        // registrador estendido exige REX.B
        assert_eq!(asm("mov r8d, 1"), vec![0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn number_conventions() {
        // bare hex, $hex, 0xhex e #decimal
        assert_eq!(parse_num("1F4"), Some(0x1F4));
        assert_eq!(parse_num("$1F4"), Some(0x1F4));
        assert_eq!(parse_num("0x1F4"), Some(0x1F4));
        assert_eq!(parse_num("#500"), Some(500));
        // (float)1000000000 -> 0x4E6E6B28 (mesmo valor do patch de XP do doador)
        assert_eq!(parse_num("(float)1000000000"), Some(0x4E6E6B28));
    }

    #[test]
    fn mov_reg_reg() {
        assert_eq!(asm("mov rbx, rax"), vec![0x48, 0x89, 0xC3]);
        assert_eq!(asm("mov eax, ecx"), vec![0x89, 0xC8]);
    }

    #[test]
    fn mov_mem() {
        // mov [rbx+0x110], eax  -> 89 83 10 01 00 00
        assert_eq!(asm("mov [rbx+0x110], eax"), vec![0x89, 0x83, 0x10, 0x01, 0x00, 0x00]);
        // mov eax, [rbx+0x110]  -> 8B 83 10 01 00 00
        assert_eq!(asm("mov eax, [rbx+0x110]"), vec![0x8B, 0x83, 0x10, 0x01, 0x00, 0x00]);
        // mov rax, [rsp]  -> SIB necessario para rsp: 48 8B 04 24
        assert_eq!(asm("mov rax, [rsp]"), vec![0x48, 0x8B, 0x04, 0x24]);
        // mov rax, [rbp]  -> rbp exige disp8=0: 48 8B 45 00
        assert_eq!(asm("mov rax, [rbp]"), vec![0x48, 0x8B, 0x45, 0x00]);
    }

    #[test]
    fn mem_with_index() {
        // mov eax, [rbx+rcx*4+8] -> 8B 44 8B 08
        assert_eq!(asm("mov eax, [rbx+rcx*4+8]"), vec![0x8B, 0x44, 0x8B, 0x08]);
    }

    #[test]
    fn mov_mem_imm() {
        // mov dword [rbx+0x10], 5 -> C7 43 10 05 00 00 00
        assert_eq!(asm("mov dword [rbx+0x10], 5"), vec![0xC7, 0x43, 0x10, 0x05, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn alu() {
        assert_eq!(asm("add eax, 1"), vec![0x81, 0xC0, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(asm("sub rax, 0x10"), vec![0x48, 0x81, 0xE8, 0x10, 0x00, 0x00, 0x00]);
        assert_eq!(asm("xor eax, eax"), vec![0x31, 0xC0]);
        // #100 = decimal 100 = 0x64
        assert_eq!(asm("cmp ebx, #100"), vec![0x81, 0xFB, 0x64, 0x00, 0x00, 0x00]);
        assert_eq!(asm("add [rbx+0x110], eax"), vec![0x01, 0x83, 0x10, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn sse_moves() {
        // movss xmm1,[rsi+3A8] -> F3 0F 10 8E A8 03 00 00 (o AOB do script de Exp)
        assert_eq!(
            asm("movss xmm1,[rsi+3A8]"),
            vec![0xF3, 0x0F, 0x10, 0x8E, 0xA8, 0x03, 0x00, 0x00]
        );
        // forma de store
        assert_eq!(
            asm("movss [rsi+3A8],xmm1"),
            vec![0xF3, 0x0F, 0x11, 0x8E, 0xA8, 0x03, 0x00, 0x00]
        );
        // movsd xmm0,xmm1 -> F2 0F 10 C1
        assert_eq!(asm("movsd xmm0,xmm1"), vec![0xF2, 0x0F, 0x10, 0xC1]);
        // registrador xmm estendido exige REX.R
        assert_eq!(asm("movss xmm8,xmm0"), vec![0xF3, 0x44, 0x0F, 0x10, 0xC0]);
    }

    #[test]
    fn sse_arith_and_movd() {
        // addss xmm0,xmm1 -> F3 0F 58 C1
        assert_eq!(asm("addss xmm0,xmm1"), vec![0xF3, 0x0F, 0x58, 0xC1]);
        // mulsd xmm2,[rax] -> F2 0F 59 10
        assert_eq!(asm("mulsd xmm2,[rax]"), vec![0xF2, 0x0F, 0x59, 0x10]);
        // movd xmm0,eax -> 66 0F 6E C0 (igual ao patch de XP do doador)
        assert_eq!(asm("movd xmm0,eax"), vec![0x66, 0x0F, 0x6E, 0xC0]);
        // movd eax,xmm0 -> 66 0F 7E C0
        assert_eq!(asm("movd eax,xmm0"), vec![0x66, 0x0F, 0x7E, 0xC0]);
        // movq xmm0,rax -> 66 48 0F 6E C0
        assert_eq!(asm("movq xmm0,rax"), vec![0x66, 0x48, 0x0F, 0x6E, 0xC0]);
    }

    #[test]
    fn mov_mem_float_imm() {
        // mov [rsi+3A8],(float)999999999 -> C7 86 A8 03 00 00 28 6B 6E 4E
        // (disp32 A8 03 00 00 + imm32 do float 28 6B 6E 4E)
        assert_eq!(
            asm("mov [rsi+3A8],(float)999999999"),
            vec![0xC7, 0x86, 0xA8, 0x03, 0x00, 0x00, 0x28, 0x6B, 0x6E, 0x4E]
        );
    }

    #[test]
    fn unary_stack_ret() {
        assert_eq!(asm("inc eax"), vec![0xFF, 0xC0]);
        assert_eq!(asm("dec rax"), vec![0x48, 0xFF, 0xC8]);
        assert_eq!(asm("push rax"), vec![0x50]);
        assert_eq!(asm("push r12"), vec![0x41, 0x54]);
        assert_eq!(asm("pop rbp"), vec![0x5D]);
        assert_eq!(asm("ret"), vec![0xC3]);
    }

    #[test]
    fn lea_and_test() {
        // lea rax, [rbx+0x10] -> 48 8D 43 10
        assert_eq!(asm("lea rax, [rbx+0x10]"), vec![0x48, 0x8D, 0x43, 0x10]);
        // test eax, eax -> 85 C0
        assert_eq!(asm("test eax, eax"), vec![0x85, 0xC0]);
    }

    #[test]
    fn unknown_mnemonic_is_none() {
        assert!(parse("frobnicate eax").is_none());
    }
}
