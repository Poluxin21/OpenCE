//! Redirecionador transparente de TCP por processo — substituto embutido do
//! Proxifier, via **WinDivert**.
//!
//! Em vez de pedir ao usuario que instale o Proxifier (pago) e crie uma regra
//! "game.exe -> proxy 127.0.0.1:porta", o Quarry usa o driver do WinDivert para
//! interceptar o TCP de SAIDA do processo alvo na pilha de rede (sem injetar no
//! jogo), reescrever o destino para o nosso listener transparente local e manter
//! um "NAT map" para restaurar o caminho de volta. O listener faz a ponte ate o
//! destino original e ja le HTTP em texto puro.
//!
//! ## Dependencia de runtime
//! Precisa de `WinDivert.dll` + `WinDivert64.sys` junto do executavel (nao e uma
//! dependencia de build: carregamos a DLL dinamicamente, entao o Quarry compila
//! e roda sem ela — so a aba de redirect fica indisponivel, com erro claro).
//! Precisa de **Administrador**. Um anticheat kernel (Vanguard) pode recusar o
//! carregamento do driver: ai funciona apenas em jogos sem AC kernel.
//!
//! ## Estado
//! O motor (reescrita de pacote) segue o padrao de "redirect para proxy local"
//! do WinDivert e usa `WinDivertHelperCalcChecksums` para os checksums. Como nao
//! da para validar sem o driver + Admin + trafego real, a direcao de reinjecao
//! pode exigir ajuste fino na maquina do usuario; os pontos sensiveis estao
//! comentados.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{GetLastError, BOOL};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::AF_INET;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

// --- WinDivert: constantes ---
const WINDIVERT_LAYER_NETWORK: i32 = 0;
/// HANDLE invalido devolvido por WinDivertOpen em caso de erro.
const INVALID_HANDLE: isize = -1;
/// Tamanho maximo de um pacote IP que lemos do driver.
const PKT_CAP: usize = 0xFFFF;

// --- WinDivert: ponteiros de funcao (resolvidos em runtime) ---
type FnOpen = unsafe extern "C" fn(*const u8, i32, i16, u64) -> isize;
type FnRecv = unsafe extern "C" fn(isize, *mut u8, u32, *mut u32, *mut WdAddress) -> BOOL;
type FnSend = unsafe extern "C" fn(isize, *const u8, u32, *mut u32, *const WdAddress) -> BOOL;
type FnClose = unsafe extern "C" fn(isize) -> BOOL;
type FnCalc = unsafe extern "C" fn(*mut u8, u32, *mut WdAddress, u64) -> BOOL;

/// `WINDIVERT_ADDRESS` (WinDivert 2.x), 80 bytes. As flags (Layer/Event/Sniffed/
/// Outbound/…) ficam empacotadas em `flags`; o resto da metadata fica na uniao.
#[repr(C)]
#[derive(Clone, Copy)]
struct WdAddress {
    timestamp: i64,
    /// bit 0..8 Layer · 8..16 Event · 16 Sniffed · 17 Outbound · 18 Loopback ·
    /// 19 Impostor · 20 IPv6 · 21 IPChecksum · 22 TCPChecksum · 23 UDPChecksum.
    flags: u32,
    reserved2: u32,
    /// Uniao (Network/Flow/Socket/Reflect) preenchida ate 64 bytes.
    union_data: [u8; 64],
}

// Garante o layout (80 bytes) em tempo de compilacao — um erro aqui quebraria
// silenciosamente a comunicacao com o driver.
const _: () = assert!(std::mem::size_of::<WdAddress>() == 80);

impl WdAddress {
    fn zeroed() -> Self {
        // SAFETY: WdAddress é um POD de inteiros/bytes; tudo-zero é válido.
        unsafe { std::mem::zeroed() }
    }
    fn set_outbound(&mut self, on: bool) {
        if on {
            self.flags |= 1 << 17;
        } else {
            self.flags &= !(1 << 17);
        }
    }
    fn ipv6(&self) -> bool {
        self.flags & (1 << 20) != 0
    }
}

/// As funcoes do WinDivert resolvidas da DLL.
struct WinDivert {
    open: FnOpen,
    recv: FnRecv,
    send: FnSend,
    close: FnClose,
    calc: FnCalc,
}

impl WinDivert {
    /// Carrega `WinDivert.dll` e resolve as funcoes. Erro claro se faltar.
    fn load() -> Result<WinDivert, String> {
        unsafe {
            let name: Vec<u16> = "WinDivert.dll\0".encode_utf16().collect();
            let module = LoadLibraryW(PCWSTR(name.as_ptr()))
                .map_err(|_| "WinDivert.dll não encontrada (coloque-a junto do quarry.exe).".to_string())?;

            macro_rules! sym {
                ($n:literal) => {{
                    let p = GetProcAddress(module, PCSTR(concat!($n, "\0").as_ptr()));
                    match p {
                        Some(f) => std::mem::transmute::<_, _>(f),
                        None => return Err(format!("símbolo {} ausente na WinDivert.dll", $n)),
                    }
                }};
            }
            Ok(WinDivert {
                open: sym!("WinDivertOpen"),
                recv: sym!("WinDivertRecv"),
                send: sym!("WinDivertSend"),
                close: sym!("WinDivertClose"),
                calc: sym!("WinDivertHelperCalcChecksums"),
            })
        }
    }
}

/// Uma conexao redirecionada, exibida na GUI.
#[derive(Clone)]
pub struct RedirectConn {
    pub client_port: u16,
    pub dst: SocketAddrV4,
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// Primeira linha HTTP em texto puro, se houver (ex.: "GET /x HTTP/1.1").
    pub http: String,
}

/// Mapa NAT: porta efêmera do cliente -> destino original (para o caminho de volta
/// e para o listener saber a quem se conectar).
type NatMap = Arc<Mutex<HashMap<u16, SocketAddrV4>>>;

/// Handle do redirecionador. O Drop encerra tudo.
pub struct RedirectHandle {
    stop: Arc<AtomicBool>,
    status: Arc<Mutex<String>>,
    conns: Arc<Mutex<Vec<RedirectConn>>>,
    pub redirected: Arc<AtomicU64>,
}

impl RedirectHandle {
    pub fn status(&self) -> String {
        self.status.lock().unwrap().clone()
    }
    pub fn conns(&self) -> Vec<RedirectConn> {
        self.conns.lock().unwrap().clone()
    }
    pub fn redirected(&self) -> u64 {
        self.redirected.load(Ordering::Relaxed)
    }
}

impl Drop for RedirectHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Sobe o redirecionador: força o TCP de saída do processo `pid` pelo listener
/// transparente em `listen_port`, que faz a ponte até o destino real.
pub fn start(pid: u32, listen_port: u16) -> Result<RedirectHandle, String> {
    let wd = WinDivert::load()?;

    let stop = Arc::new(AtomicBool::new(false));
    let status = Arc::new(Mutex::new("iniciando…".to_string()));
    let conns: Arc<Mutex<Vec<RedirectConn>>> = Arc::new(Mutex::new(Vec::new()));
    let redirected = Arc::new(AtomicU64::new(0));
    let nat: NatMap = Arc::new(Mutex::new(HashMap::new()));

    // Conjunto de portas locais do alvo, atualizado periodicamente.
    let target_ports: Arc<Mutex<HashSet<u16>>> = Arc::new(Mutex::new(tcp_ports_for_pid(pid)));

    // 1) listener transparente (faz a ponte cliente <-> destino original)
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, listen_port))
        .map_err(|e| format!("não consegui abrir o listener :{listen_port}: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("listener nonblocking: {e}"))?;
    spawn_listener(listener, nat.clone(), conns.clone(), stop.clone());

    // 2) atualizador das portas do alvo
    {
        let (ports, stop, status) = (target_ports.clone(), stop.clone(), status.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let p = tcp_ports_for_pid(pid);
                if p.is_empty() {
                    *status.lock().unwrap() =
                        format!("redirecionando pid {pid} (sem conexões TCP no momento)");
                } else {
                    *status.lock().unwrap() =
                        format!("redirecionando pid {pid} · {} portas ativas", p.len());
                }
                *ports.lock().unwrap() = p;
                sleep_checked(&stop, 1000);
            }
        });
    }

    // 3) thread do WinDivert (recebe, reescreve e reinjeta)
    {
        let (stop, nat, target_ports, redirected, status) = (
            stop.clone(),
            nat.clone(),
            target_ports.clone(),
            redirected.clone(),
            status.clone(),
        );
        std::thread::spawn(move || {
            if let Err(e) = divert_loop(&wd, listen_port, stop.clone(), nat, target_ports, redirected)
            {
                *status.lock().unwrap() = format!("erro: {e}");
                stop.store(true, Ordering::Relaxed);
            }
        });
    }

    Ok(RedirectHandle {
        stop,
        status,
        conns,
        redirected,
    })
}

/// Loop principal do WinDivert: filtra TCP de saída, reescreve cliente->servidor
/// para o listener local e servidor->cliente de volta para o destino original.
fn divert_loop(
    wd: &WinDivert,
    listen_port: u16,
    stop: Arc<AtomicBool>,
    nat: NatMap,
    target_ports: Arc<Mutex<HashSet<u16>>>,
    redirected: Arc<AtomicU64>,
) -> Result<(), String> {
    // Só TCP, só IPv4, fora o nosso próprio loopback do listener. O PID é filtrado
    // em código (via portas do alvo), porque a camada NETWORK não expõe o PID.
    let filter = b"outbound and ip and tcp\0";
    let handle = unsafe { (wd.open)(filter.as_ptr(), WINDIVERT_LAYER_NETWORK, 0, 0) };
    if handle == INVALID_HANDLE {
        let code = unsafe { GetLastError().0 };
        return Err(match code {
            5 => "acesso negado ao WinDivert — rode o Quarry como Administrador.".into(),
            2 | 3 => "WinDivert64.sys não encontrado (coloque-o junto do quarry.exe).".into(),
            1275 => "driver WinDivert bloqueado (provável anticheat/Driver Signature).".into(),
            other => format!("WinDivertOpen falhou (erro {other})."),
        });
    }
    let _guard = HandleGuard(handle, wd.close);

    let mut buf = vec![0u8; PKT_CAP];
    let mut addr = WdAddress::zeroed();
    while !stop.load(Ordering::Relaxed) {
        let mut len: u32 = 0;
        let ok = unsafe {
            (wd.recv)(
                handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut len,
                &mut addr,
            )
        };
        if !ok.as_bool() {
            // timeout/erro transitório: continua para reavaliar `stop`
            continue;
        }
        let n = len as usize;
        if addr.ipv6() || n < 20 {
            let _ = unsafe { (wd.send)(handle, buf.as_ptr(), len, std::ptr::null_mut(), &addr) };
            continue;
        }

        let mutated = rewrite_packet(
            &mut buf[..n],
            &mut addr,
            listen_port,
            &nat,
            &target_ports,
            &redirected,
        );
        if mutated {
            // recalcula checksums de IP/TCP depois da reescrita
            let _ = unsafe { (wd.calc)(buf.as_mut_ptr(), len, &mut addr, 0) };
        }
        // reinjeta (modificado ou intacto) para o pacote seguir seu curso
        let _ = unsafe { (wd.send)(handle, buf.as_ptr(), len, std::ptr::null_mut(), &addr) };
    }
    Ok(())
}

/// Reescreve um pacote IPv4+TCP no lugar. Devolve `true` se mexeu nele.
///
/// - cliente->servidor (porta de origem é do alvo): guarda o destino original no
///   NAT map e redireciona para `clientIp:listen_port` (continua de saída).
/// - servidor->cliente (porta de ORIGEM == listen_port): restaura o destino
///   original como ORIGEM e reinjeta como ENTRADA para o socket do cliente.
fn rewrite_packet(
    pkt: &mut [u8],
    addr: &mut WdAddress,
    listen_port: u16,
    nat: &NatMap,
    target_ports: &Arc<Mutex<HashSet<u16>>>,
    redirected: &Arc<AtomicU64>,
) -> bool {
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt[9] != 6 || pkt.len() < ihl + 20 {
        return false; // não é TCP ou é curto demais
    }
    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);

    // --- caminho de volta: listener -> cliente ---
    if src_port == listen_port {
        let orig = nat.lock().unwrap().get(&dst_port).copied();
        let Some(orig) = orig else {
            return false; // sem mapeamento: deixa passar
        };
        // origem passa a ser o destino original (o cliente "acha" que fala com o servidor)
        write_ip(pkt, 12, *orig.ip()); // src_ip := destino original
        write_port(pkt, ihl, orig.port()); // src_port := porta original
        // entrega ao socket do cliente como pacote de ENTRADA
        addr.set_outbound(false);
        return true;
    }

    // --- caminho de ida: cliente(alvo) -> servidor ---
    let is_target = target_ports.lock().unwrap().contains(&src_port);
    if !is_target || dst_ip.is_loopback() {
        return false;
    }
    // guarda o destino real e redireciona para o listener local (no mesmo IP)
    nat.lock()
        .unwrap()
        .insert(src_port, SocketAddrV4::new(dst_ip, dst_port));
    redirected.fetch_add(1, Ordering::Relaxed);
    write_ip(pkt, 16, src_ip); // dst_ip := IP local do cliente (entrega local)
    write_port(pkt, ihl + 2, listen_port); // dst_port := listener
    true
}

fn write_ip(pkt: &mut [u8], off: usize, ip: Ipv4Addr) {
    pkt[off..off + 4].copy_from_slice(&ip.octets());
}
fn write_port(pkt: &mut [u8], off: usize, port: u16) {
    pkt[off..off + 2].copy_from_slice(&port.to_be_bytes());
}

/// Aceita conexões redirecionadas, descobre o destino original pelo NAT map e
/// faz a ponte bidirecional, registrando endpoints/volume e a 1ª linha HTTP.
fn spawn_listener(
    listener: TcpListener,
    nat: NatMap,
    conns: Arc<Mutex<Vec<RedirectConn>>>,
    stop: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((client, peer)) => {
                    let SocketAddr::V4(peer) = peer else { continue };
                    let dst = nat.lock().unwrap().get(&peer.port()).copied();
                    let Some(dst) = dst else {
                        continue; // ainda não mapeado; descarta
                    };
                    let (conns, stop) = (conns.clone(), stop.clone());
                    std::thread::spawn(move || {
                        bridge(client, peer.port(), dst, conns, stop);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    sleep_checked(&stop, 100);
                }
                Err(_) => sleep_checked(&stop, 100),
            }
        }
    });
}

/// Ponte cliente <-> destino original, com tap de HTTP em texto puro.
fn bridge(
    client: TcpStream,
    client_port: u16,
    dst: SocketAddrV4,
    conns: Arc<Mutex<Vec<RedirectConn>>>,
    stop: Arc<AtomicBool>,
) {
    let server = match TcpStream::connect(dst) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = client.set_read_timeout(Some(Duration::from_millis(200)));
    let _ = server.set_read_timeout(Some(Duration::from_millis(200)));

    let idx = {
        let mut v = conns.lock().unwrap();
        v.push(RedirectConn {
            client_port,
            dst,
            bytes_up: 0,
            bytes_down: 0,
            http: String::new(),
        });
        v.len() - 1
    };

    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));

    // cliente -> servidor (com sniff da 1ª linha HTTP)
    let c2s = {
        let (mut r, mut w) = (client.try_clone().ok(), server.try_clone().ok());
        let (conns, up, stop) = (conns.clone(), up.clone(), stop.clone());
        std::thread::spawn(move || {
            let (Some(r), Some(w)) = (r.as_mut(), w.as_mut()) else { return };
            let mut sniffed = false;
            let mut b = [0u8; 16384];
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match r.read(&mut b) {
                    Ok(0) => break,
                    Ok(n) => {
                        if !sniffed {
                            if let Some(line) = http_line(&b[..n]) {
                                conns.lock().unwrap().get_mut(idx).map(|c| c.http = line);
                            }
                            sniffed = true;
                        }
                        if w.write_all(&b[..n]).is_err() {
                            break;
                        }
                        up.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                }
            }
        })
    };
    // servidor -> cliente
    let s2c = {
        let (mut r, mut w) = (server.try_clone().ok(), client.try_clone().ok());
        let (down, stop) = (down.clone(), stop.clone());
        std::thread::spawn(move || {
            let (Some(r), Some(w)) = (r.as_mut(), w.as_mut()) else { return };
            let mut b = [0u8; 16384];
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match r.read(&mut b) {
                    Ok(0) => break,
                    Ok(n) => {
                        if w.write_all(&b[..n]).is_err() {
                            break;
                        }
                        down.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                }
            }
        })
    };
    let _ = c2s.join();
    let _ = s2c.join();

    // atualiza contadores finais
    if let Some(c) = conns.lock().unwrap().get_mut(idx) {
        c.bytes_up = up.load(Ordering::Relaxed);
        c.bytes_down = down.load(Ordering::Relaxed);
    }
}

/// Primeira linha de uma requisição HTTP em texto puro, se for o caso.
fn http_line(buf: &[u8]) -> Option<String> {
    const M: [&[u8]; 7] = [
        b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ", b"OPTIONS",
    ];
    if !M.iter().any(|m| buf.starts_with(m)) {
        return None;
    }
    let end = buf.iter().position(|&b| b == b'\r').unwrap_or(buf.len().min(120));
    Some(String::from_utf8_lossy(&buf[..end]).trim().to_string())
}

/// Portas TCP locais pertencentes ao processo `pid` (via tabela do Windows).
fn tcp_ports_for_pid(pid: u32) -> HashSet<u16> {
    let mut out = HashSet::new();
    unsafe {
        let af = AF_INET.0 as u32;
        let mut size = 0u32;
        GetExtendedTcpTable(None, &mut size, BOOL(0), af, TCP_TABLE_OWNER_PID_ALL, 0);
        if size == 0 {
            return out;
        }
        let mut buf = vec![0u8; size as usize];
        let r = GetExtendedTcpTable(
            Some(buf.as_mut_ptr().cast()),
            &mut size,
            BOOL(0),
            af,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if r != 0 {
            return out;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(
            table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID,
            table.dwNumEntries as usize,
        );
        for row in rows {
            if row.dwOwningPid == pid {
                // porta vem em network byte order na low word
                out.insert(((row.dwLocalPort & 0xFFFF) as u16).swap_bytes());
            }
        }
    }
    out
}

/// Dorme `ms` em fatias de 50ms, abortando se `stop` virar true.
fn sleep_checked(stop: &Arc<AtomicBool>, ms: u64) {
    let mut left = ms;
    while left > 0 && !stop.load(Ordering::Relaxed) {
        let step = left.min(50);
        std::thread::sleep(Duration::from_millis(step));
        left -= step;
    }
}

/// Fecha o handle do WinDivert no fim do escopo.
struct HandleGuard(isize, FnClose);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        let _ = unsafe { (self.1)(self.0) };
    }
}
