//! Camada de scripting / automacao, sobre o motor [`rhai`] (Rust puro).
//!
//! Expoe ao script funcoes de leitura/escrita de memoria, base de modulos e AOB
//! scan, todas operando no processo anexado. O `Engine` e construido e executado
//! inteiramente dentro da thread de fundo do chamador, entao nada do rhai precisa
//! cruzar fronteiras de thread (sem a feature `sync`): basta que os dados movidos
//! para a thread (o handle Arc, as bases dos modulos) sejam `Send`.
//!
//! API disponivel no script (enderecos e valores sao inteiros de 64 bits):
//!   read_i8/read_i16/read_i32/read_i64/read_u32(addr)   -> int
//!   read_f32/read_f64(addr)                              -> float
//!   read_ptr(addr)         -> int   (4 ou 8 bytes conforme a arquitetura)
//!   read_bytes(addr, len)  -> array de int
//!   write_i32/write_i64(addr, val)    -> bool
//!   write_f32/write_f64(addr, val)    -> bool
//!   write_bytes(addr, array)          -> bool
//!   module_base(nome)      -> int   (0 se nao carregado)
//!   aob_scan(padrao)              -> int  (primeiro endereco, 0 se nada)
//!   aob_scan_module(modulo, padrao) -> int
//!   print(x) / debug(x)    -> vao para a saida do script

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rhai::{Array, Dynamic, Engine, ImmutableString};

use crate::inject;
use crate::memory::{self, Region};
use crate::process::OpenProcessHandle;

/// Resultado de uma execucao: linhas de saida (print/debug) e erro opcional.
pub struct ScriptResult {
    pub output: Vec<String>,
    pub error: Option<String>,
}

/// Script de exemplo mostrado por padrao na aba.
pub const SAMPLE: &str = "\
// Exemplo: lê um valor e escreve outro.
// 'attach' um processo antes de executar.
let base = module_base(\"game.exe\");
print(\"game.exe base = \" + base);

// let hp = read_i32(base + 0x10C);
// print(\"hp = \" + hp);
// write_i32(base + 0x10C, 999);

// AOB scan (curinga ??):
// let hit = aob_scan(\"89 83 A4 00 00 00\");
// print(\"achei em \" + hit);
";

/// Executa `src` no processo `handle`. Deve rodar numa thread de fundo: pode
/// fazer AOB scan (varre a memoria toda) e demorar.
pub fn run(
    handle: Arc<OpenProcessHandle>,
    ptr_size: usize,
    module_bases: HashMap<String, u64>,
    src: &str,
) -> ScriptResult {
    let out = Arc::new(Mutex::new(Vec::<String>::new()));

    let mut engine = Engine::new();
    // Teto de operacoes: evita que um loop infinito no script trave a thread.
    engine.set_max_operations(100_000_000);
    engine.set_max_call_levels(64);

    {
        let o = out.clone();
        engine.on_print(move |s| o.lock().unwrap().push(s.to_string()));
    }
    {
        let o = out.clone();
        engine.on_debug(move |s, _src, pos| {
            o.lock().unwrap().push(format!("[debug {pos:?}] {s}"))
        });
    }

    register_memory(&mut engine, handle.clone(), ptr_size);
    register_scan(&mut engine, handle.clone(), module_bases);

    let error = match engine.run(src) {
        Ok(()) => None,
        Err(e) => Some(e.to_string()),
    };

    let output = Arc::try_unwrap(out)
        .map(|m| m.into_inner().unwrap())
        .unwrap_or_default();
    ScriptResult { output, error }
}

/// Registra as funcoes de leitura/escrita de memoria.
fn register_memory(engine: &mut Engine, handle: Arc<OpenProcessHandle>, ptr_size: usize) {
    // ---- leituras inteiras ----
    macro_rules! read_int {
        ($name:literal, $ty:ty, $len:expr) => {{
            let h = handle.clone();
            engine.register_fn($name, move |addr: i64| -> i64 {
                memory::read_bytes(h.raw(), addr as u64, $len)
                    .and_then(|b| b.get(..$len).map(|s| s.try_into().ok()).flatten())
                    .map(|a| <$ty>::from_le_bytes(a) as i64)
                    .unwrap_or(0)
            });
        }};
    }
    read_int!("read_i8", i8, 1);
    read_int!("read_i16", i16, 2);
    read_int!("read_i32", i32, 4);
    read_int!("read_i64", i64, 8);
    read_int!("read_u32", u32, 4);

    // ---- leituras float ----
    {
        let h = handle.clone();
        engine.register_fn("read_f32", move |addr: i64| -> f64 {
            memory::read_bytes(h.raw(), addr as u64, 4)
                .and_then(|b| b.get(..4).and_then(|s| s.try_into().ok()))
                .map(|a| f32::from_le_bytes(a) as f64)
                .unwrap_or(0.0)
        });
    }
    {
        let h = handle.clone();
        engine.register_fn("read_f64", move |addr: i64| -> f64 {
            memory::read_bytes(h.raw(), addr as u64, 8)
                .and_then(|b| b.get(..8).and_then(|s| s.try_into().ok()))
                .map(f64::from_le_bytes)
                .unwrap_or(0.0)
        });
    }

    // ---- ponteiro com largura da arquitetura ----
    {
        let h = handle.clone();
        engine.register_fn("read_ptr", move |addr: i64| -> i64 {
            memory::read_ptr(h.raw(), addr as u64, ptr_size)
                .map(|v| v as i64)
                .unwrap_or(0)
        });
    }

    // ---- bytes crus ----
    {
        let h = handle.clone();
        engine.register_fn("read_bytes", move |addr: i64, len: i64| -> Array {
            memory::read_bytes(h.raw(), addr as u64, len.max(0) as usize)
                .unwrap_or_default()
                .into_iter()
                .map(|b| Dynamic::from(b as i64))
                .collect()
        });
    }

    // ---- escritas ----
    {
        let h = handle.clone();
        engine.register_fn("write_i32", move |addr: i64, val: i64| -> bool {
            memory::write_bytes(h.raw(), addr as u64, &(val as i32).to_le_bytes())
        });
    }
    {
        let h = handle.clone();
        engine.register_fn("write_i64", move |addr: i64, val: i64| -> bool {
            memory::write_bytes(h.raw(), addr as u64, &val.to_le_bytes())
        });
    }
    {
        let h = handle.clone();
        engine.register_fn("write_f32", move |addr: i64, val: f64| -> bool {
            memory::write_bytes(h.raw(), addr as u64, &(val as f32).to_le_bytes())
        });
    }
    {
        let h = handle.clone();
        engine.register_fn("write_f64", move |addr: i64, val: f64| -> bool {
            memory::write_bytes(h.raw(), addr as u64, &val.to_le_bytes())
        });
    }
    {
        let h = handle.clone();
        engine.register_fn("write_bytes", move |addr: i64, arr: Array| -> bool {
            let bytes: Vec<u8> = arr.iter().map(|d| d.as_int().unwrap_or(0) as u8).collect();
            memory::write_bytes(h.raw(), addr as u64, &bytes)
        });
    }
}

/// Registra base de modulos e AOB scan.
fn register_scan(
    engine: &mut Engine,
    handle: Arc<OpenProcessHandle>,
    module_bases: HashMap<String, u64>,
) {
    {
        let mb = module_bases.clone();
        engine.register_fn("module_base", move |name: ImmutableString| -> i64 {
            mb.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name.as_str()))
                .map(|(_, v)| *v as i64)
                .unwrap_or(0)
        });
    }
    {
        let h = handle.clone();
        engine.register_fn("aob_scan", move |pattern: ImmutableString| -> i64 {
            let Some(pat) = inject::parse_aob(pattern.as_str()) else {
                return 0;
            };
            let regions = memory::enumerate_regions(h.raw());
            inject::aob_scan(h.raw(), &regions, &pat, 1)
                .into_iter()
                .next()
                .map(|a| a as i64)
                .unwrap_or(0)
        });
    }
    {
        let h = handle.clone();
        engine.register_fn(
            "aob_scan_module",
            move |module: ImmutableString, pattern: ImmutableString| -> i64 {
                let Some(pat) = inject::parse_aob(pattern.as_str()) else {
                    return 0;
                };
                // restringe a varredura as regioes dentro do modulo
                let mods = inject::list_modules(h.pid);
                let Some(m) = mods.iter().find(|m| m.name.eq_ignore_ascii_case(module.as_str()))
                else {
                    return 0;
                };
                let (base, end) = (m.base, m.base + m.size as u64);
                let regions: Vec<Region> = memory::enumerate_regions(h.raw())
                    .into_iter()
                    .filter(|r| r.base >= base && r.base < end)
                    .collect();
                inject::aob_scan(h.raw(), &regions, &pat, 1)
                    .into_iter()
                    .next()
                    .map(|a| a as i64)
                    .unwrap_or(0)
            },
        );
    }
}
