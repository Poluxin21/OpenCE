//! Import de tabelas `.CT` do Cheat Engine.
//!
//! O `.CT` e um XML: `<CheatTable><CheatEntries><CheatEntry>...`. Cada entrada
//! tem descricao, tipo de variavel, endereco (absoluto, `modulo.exe+offset` ou
//! base de um ponteiro) e, quando e ponteiro, uma lista de `<Offset>`. Entradas
//! podem ser aninhadas (pastas), entao achatamos a arvore.
//!
//! Este modulo so faz o *parse* — devolve [`CeEntry`] cruas. Quem chama
//! (a GUI) resolve `modulo+offset` para um endereco real usando as bases dos
//! modulos do processo anexado e converte em entradas da cheat table.

use crate::value::ValueType;

/// Uma entrada importada de um `.CT`, ainda nao resolvida para endereco final.
#[derive(Clone, Debug)]
pub struct CeEntry {
    pub desc: String,
    /// `None` quando o tipo nao tem equivalente no Quarry (AoB, script, pasta).
    pub value_type: Option<ValueType>,
    /// Nome do modulo (ex. `game.exe`) quando o endereco e relativo a um modulo.
    pub module: Option<String>,
    /// Offset dentro do modulo, ou o endereco absoluto quando `module` e `None`.
    pub base: u64,
    /// Offsets do ponteiro ja na ordem base -> alvo (revertida em relacao ao CE).
    pub offsets: Vec<u64>,
    /// Bytes a ler para tipos string (0 para numericos).
    pub str_len: usize,
}

impl CeEntry {
    /// True quando a entrada e um ponteiro (tem ao menos um offset).
    pub fn is_pointer(&self) -> bool {
        !self.offsets.is_empty()
    }
}

/// Eventos minimos de XML que nos interessam.
enum Tok {
    Start(String),
    End(String),
    Text(String),
}

/// Tokeniza o XML em start/end/text, ignorando atributos, comentarios,
/// declaracoes (`<?...?>`) e CDATA. Tags auto-fechadas (`<x/>`) viram Start+End.
fn tokenize(xml: &str) -> Vec<Tok> {
    let b = xml.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'<' {
            // comentario / CDATA / declaracao / DOCTYPE: pula ate '>'
            if xml[i..].starts_with("<!--") {
                if let Some(end) = xml[i..].find("-->") {
                    i += end + 3;
                } else {
                    break;
                }
                continue;
            }
            if b.get(i + 1) == Some(&b'?') || b.get(i + 1) == Some(&b'!') {
                if let Some(end) = xml[i..].find('>') {
                    i += end + 1;
                } else {
                    break;
                }
                continue;
            }
            let Some(rel) = xml[i..].find('>') else { break };
            let inner = &xml[i + 1..i + rel]; // conteudo entre '<' e '>'
            i += rel + 1;
            let inner_trim = inner.trim();
            if let Some(name) = inner_trim.strip_prefix('/') {
                toks.push(Tok::End(tag_name(name)));
            } else {
                let self_close = inner_trim.ends_with('/');
                let name = tag_name(inner_trim);
                toks.push(Tok::Start(name.clone()));
                if self_close {
                    toks.push(Tok::End(name));
                }
            }
        } else {
            let start = i;
            while i < b.len() && b[i] != b'<' {
                i += 1;
            }
            let text = unescape(&xml[start..i]);
            if !text.trim().is_empty() {
                toks.push(Tok::Text(text));
            }
        }
    }
    toks
}

/// Extrai o nome da tag (ate o primeiro espaco/`/`), em minusculas para casar
/// sem depender da capitalizacao.
fn tag_name(s: &str) -> String {
    let end = s
        .find(|c: char| c.is_whitespace() || c == '/')
        .unwrap_or(s.len());
    s[..end].to_ascii_lowercase()
}

/// Desfaz as entidades XML mais comuns.
fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        if let Some(semi) = rest.find(';') {
            let ent = &rest[1..semi];
            match ent {
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "amp" => out.push('&'),
                "quot" => out.push('"'),
                "apos" => out.push('\''),
                _ => {
                    let ch = ent
                        .strip_prefix("#x")
                        .or_else(|| ent.strip_prefix("#X"))
                        .and_then(|h| u32::from_str_radix(h, 16).ok())
                        .or_else(|| ent.strip_prefix('#').and_then(|d| d.parse::<u32>().ok()))
                        .and_then(char::from_u32);
                    match ch {
                        Some(c) => out.push(c),
                        None => out.push_str(&rest[..=semi]), // entidade desconhecida: mantem
                    }
                }
            }
            rest = &rest[semi + 1..];
        } else {
            out.push('&');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    out
}

/// Construtor de uma entrada enquanto ainda estamos dentro do seu `<CheatEntry>`.
#[derive(Default)]
struct Builder {
    desc: String,
    var_type: String,
    address: String,
    offsets: Vec<u64>,
    length: Option<usize>,
    unicode: bool,
}

/// Faz o parse de um `.CT` inteiro, achatando entradas aninhadas. Retorna apenas
/// as entradas com endereco e tipo reconheciveis (pastas/scripts sao puladas).
pub fn parse(xml: &str) -> Result<Vec<CeEntry>, String> {
    let toks = tokenize(xml);
    if !toks
        .iter()
        .any(|t| matches!(t, Tok::Start(n) if n == "cheatentry"))
    {
        return Err("nenhum <CheatEntry> encontrado — o arquivo e um .CT valido?".into());
    }

    let mut out = Vec::new();
    let mut stack: Vec<Builder> = Vec::new(); // entradas abertas (aninhamento)
    let mut cur_tag = String::new(); // ultima tag aberta (dona do proximo texto)
    let mut in_offsets = false;

    for tok in &toks {
        match tok {
            Tok::Start(name) => {
                cur_tag = name.clone();
                match name.as_str() {
                    "cheatentry" => stack.push(Builder::default()),
                    "offsets" => in_offsets = true,
                    _ => {}
                }
            }
            Tok::End(name) => {
                match name.as_str() {
                    "offsets" => in_offsets = false,
                    "cheatentry" => {
                        if let Some(b) = stack.pop() {
                            if let Some(e) = finalize(b) {
                                out.push(e);
                            }
                        }
                    }
                    _ => {}
                }
                cur_tag.clear();
            }
            Tok::Text(text) => {
                let Some(b) = stack.last_mut() else { continue };
                match cur_tag.as_str() {
                    "description" => b.desc = strip_quotes(text).to_string(),
                    "variabletype" => b.var_type = text.trim().to_string(),
                    "address" => b.address = text.trim().to_string(),
                    "length" => b.length = text.trim().parse::<usize>().ok(),
                    "unicode" => b.unicode = text.trim() == "1",
                    "offset" if in_offsets => {
                        if let Some(v) = parse_hex(text) {
                            b.offsets.push(v);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(out)
}

/// Converte um [`Builder`] cru numa [`CeEntry`], ou `None` se nao for util.
fn finalize(b: Builder) -> Option<CeEntry> {
    let value_type = map_type(&b.var_type, b.unicode);
    // Sem tipo reconhecido e sem ponteiro nao ha o que salvar (pasta/script).
    if value_type.is_none() && b.offsets.is_empty() {
        return None;
    }
    let (module, base) = parse_address(&b.address)?;

    let str_len = if matches!(
        value_type,
        Some(ValueType::StringUtf8) | Some(ValueType::StringUtf16)
    ) {
        let chars = b.length.unwrap_or(16).max(1);
        if b.unicode {
            chars * 2
        } else {
            chars
        }
    } else {
        0
    };

    // CE lista os offsets do mais externo (ultimo aplicado) para o mais interno
    // (primeiro deref). O PtrPath do Quarry usa a ordem base -> alvo, entao
    // revertemos.
    let mut offsets = b.offsets;
    offsets.reverse();

    Some(CeEntry {
        desc: b.desc,
        value_type,
        module,
        base,
        offsets,
        str_len,
    })
}

/// Mapeia o `VariableType` do CE para o [`ValueType`] do Quarry.
fn map_type(t: &str, unicode: bool) -> Option<ValueType> {
    match t.trim().to_ascii_lowercase().as_str() {
        "byte" => Some(ValueType::I8),
        "2 bytes" => Some(ValueType::I16),
        "4 bytes" => Some(ValueType::I32),
        "8 bytes" => Some(ValueType::I64),
        "float" => Some(ValueType::F32),
        "double" => Some(ValueType::F64),
        "string" => Some(if unicode {
            ValueType::StringUtf16
        } else {
            ValueType::StringUtf8
        }),
        // AoB, binary, "auto assembler script", agrupadores: sem equivalente.
        _ => None,
    }
}

/// Interpreta um endereco do CE: `"game.exe"+1A2B`, `game.exe+1A2B`, `1A2B` ou
/// `0x1A2B`. Retorna `(modulo, offset/endereco)`.
fn parse_address(addr: &str) -> Option<(Option<String>, u64)> {
    let addr = addr.trim();
    if addr.is_empty() {
        return None;
    }
    if let Some(plus) = addr.find('+') {
        let module = strip_quotes(&addr[..plus]).trim().to_string();
        let off = parse_hex(&addr[plus + 1..])?;
        if module.is_empty() {
            Some((None, off))
        } else {
            Some((Some(module), off))
        }
    } else {
        // sem '+': endereco absoluto em hex, ou um modulo "puro" (offset 0).
        match parse_hex(addr) {
            Some(v) => Some((None, v)),
            None => {
                let m = strip_quotes(addr).trim().to_string();
                if m.is_empty() {
                    None
                } else {
                    Some((Some(m), 0))
                }
            }
        }
    }
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

/// Remove aspas em volta de um texto (`"game.exe"` -> `game.exe`).
fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_and_pointer_entries() {
        let xml = r#"<?xml version="1.0"?>
        <CheatTable>
          <CheatEntries>
            <CheatEntry>
              <Description>"Health"</Description>
              <VariableType>4 Bytes</VariableType>
              <Address>game.exe+1A2B3C</Address>
            </CheatEntry>
            <CheatEntry>
              <Description>"Ammo (ptr)"</Description>
              <VariableType>Float</VariableType>
              <Address>"game.exe"+100</Address>
              <Offsets>
                <Offset>30</Offset>
                <Offset>10</Offset>
              </Offsets>
            </CheatEntry>
            <CheatEntry>
              <Description>"Folder"</Description>
            </CheatEntry>
          </CheatEntries>
        </CheatTable>"#;
        let e = parse(xml).unwrap();
        assert_eq!(e.len(), 2); // a pasta sem tipo/offset e ignorada

        assert_eq!(e[0].desc, "Health");
        assert_eq!(e[0].value_type, Some(ValueType::I32));
        assert_eq!(e[0].module.as_deref(), Some("game.exe"));
        assert_eq!(e[0].base, 0x1A2B3C);
        assert!(!e[0].is_pointer());

        assert_eq!(e[1].value_type, Some(ValueType::F32));
        assert!(e[1].is_pointer());
        assert_eq!(e[1].base, 0x100);
        // revertido para a ordem base -> alvo
        assert_eq!(e[1].offsets, vec![0x10, 0x30]);
    }

    #[test]
    fn parses_absolute_and_string() {
        let xml = r#"<CheatTable><CheatEntries>
          <CheatEntry><Description>"Abs"</Description>
            <VariableType>8 Bytes</VariableType><Address>7FF600001000</Address></CheatEntry>
          <CheatEntry><Description>"Name"</Description>
            <VariableType>String</VariableType><Length>12</Length><Unicode>1</Unicode>
            <Address>game.exe+50</Address></CheatEntry>
        </CheatEntries></CheatTable>"#;
        let e = parse(xml).unwrap();
        assert_eq!(e[0].module, None);
        assert_eq!(e[0].base, 0x7FF600001000);
        assert_eq!(e[1].value_type, Some(ValueType::StringUtf16));
        assert_eq!(e[1].str_len, 24); // 12 chars * 2 (unicode)
    }
}
