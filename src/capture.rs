//! Captura passiva de rede (somente metadados) da secao Kernel Exploring.
//!
//! Abre um socket RAW do Winsock numa interface IPv4 e liga o modo
//! `SIO_RCVALL` (promiscuo a nivel de IP). Cada pacote IPv4 e dissecado apenas
//! no cabecalho — IPs, portas, protocolo e tamanho — para mapear endpoints,
//! volume e timing SEM olhar o conteudo (que e cifrado). Nao toca no processo
//! alvo: funciona com qualquer jogo, inclusive sob anticheat kernel.
//!
//! Roda em thread propria; a GUI le os agregados via [`CaptureShared`]. Precisa
//! de privilegios de Administrador (o Quarry ja exige isso).

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use windows::Win32::Networking::WinSock::{
    bind, closesocket, recv, setsockopt, socket, WSACleanup, WSAGetLastError, WSAIoctl, WSAStartup,
    ADDRESS_FAMILY, AF_INET, INVALID_SOCKET, IN_ADDR, IN_ADDR_0, IPPROTO_IP, SEND_RECV_FLAGS,
    SIO_RCVALL, SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR, SOCK_RAW, SOL_SOCKET, SO_RCVTIMEO,
    WSADATA, WSAETIMEDOUT,
};

/// Uma "conversa" agregada por (protocolo, porta local, IP remoto, porta remota).
#[derive(Clone)]
pub struct Conversation {
    pub proto: u8,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub packets: u64,
    pub bytes: u64,
    pub last_ms: u64,
}

impl Conversation {
    pub fn proto_name(&self) -> &'static str {
        match self.proto {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            _ => "IP",
        }
    }
}

/// Estado compartilhado entre a GUI e a thread de captura.
pub struct CaptureShared {
    pub convs: Mutex<Vec<Conversation>>,
    pub total_packets: AtomicU64,
    pub total_bytes: AtomicU64,
    running: AtomicBool,
}

/// Handle da captura em execucao, mantido pela GUI. O Drop encerra a thread.
pub struct CaptureHandle {
    pub shared: Arc<CaptureShared>,
    status: Arc<Mutex<String>>,
}

impl CaptureHandle {
    pub fn status(&self) -> String {
        self.status.lock().unwrap().clone()
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.shared.running.store(false, Ordering::Relaxed);
    }
}

/// Limite de conversas distintas guardadas (evita crescer sem fim).
const MAX_CONVS: usize = 4000;

/// Descobre o IPv4 da interface de saida primaria (o "truque do UDP connect":
/// nenhum pacote e enviado, mas o SO escolhe a rota e revela o IP local).
pub fn primary_ipv4() -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    match sock.local_addr().ok()? {
        std::net::SocketAddr::V4(a) => Some(*a.ip()),
        _ => None,
    }
}

/// Sobe a captura numa thread propria e devolve o handle imediatamente.
pub fn start(iface: Ipv4Addr) -> CaptureHandle {
    let shared = Arc::new(CaptureShared {
        convs: Mutex::new(Vec::new()),
        total_packets: AtomicU64::new(0),
        total_bytes: AtomicU64::new(0),
        running: AtomicBool::new(true),
    });
    let status = Arc::new(Mutex::new(String::from("iniciando…")));

    let shared_t = shared.clone();
    let status_t = status.clone();
    std::thread::spawn(move || {
        if let Err(e) = capture_loop(iface, &shared_t, &status_t) {
            *status_t.lock().unwrap() = format!("erro: {e}");
            shared_t.running.store(false, Ordering::Relaxed);
        }
    });

    CaptureHandle { shared, status }
}

/// Loop de recepcao. Roda ate `running` virar false (checado a cada timeout).
fn capture_loop(
    iface: Ipv4Addr,
    shared: &Arc<CaptureShared>,
    status: &Arc<Mutex<String>>,
) -> Result<(), String> {
    unsafe {
        let mut wsadata = WSADATA::default();
        if WSAStartup(0x0202, &mut wsadata) != 0 {
            return Err("WSAStartup falhou".into());
        }
        // garante WSACleanup ao sair, qualquer que seja o caminho
        let _cleanup = WsaCleanupGuard;

        let sock = socket(AF_INET.0 as i32, SOCK_RAW, IPPROTO_IP.0)
            .map_err(|e| format!("socket() falhou: {e}"))?;
        if sock == INVALID_SOCKET {
            return Err(format!("socket() falhou (erro {})", WSAGetLastError().0));
        }
        let _closer = SocketGuard(sock);

        // bind na interface escolhida (obrigatorio para SIO_RCVALL)
        let addr = SOCKADDR_IN {
            sin_family: ADDRESS_FAMILY(AF_INET.0),
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(iface.octets()),
                },
            },
            sin_zero: [0; 8],
        };
        if bind(
            sock,
            &addr as *const SOCKADDR_IN as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        ) == SOCKET_ERROR
        {
            return Err(format!(
                "bind({iface}) falhou (erro {}). Use o IP de uma placa de rede real.",
                WSAGetLastError().0
            ));
        }

        // timeout de recv para poder checar o flag de parada
        let timeout_ms: u32 = 500;
        let _ = setsockopt(
            sock,
            SOL_SOCKET,
            SO_RCVTIMEO,
            Some(&timeout_ms.to_ne_bytes()),
        );

        // liga o modo promiscuo a nivel IP (recebe todo trafego da interface)
        let optval: u32 = 1; // RCVALL_ON
        let mut bytes_ret: u32 = 0;
        if WSAIoctl(
            sock,
            SIO_RCVALL,
            Some(&optval as *const u32 as *const _),
            std::mem::size_of::<u32>() as u32,
            None,
            0,
            &mut bytes_ret,
            None,
            None,
        ) == SOCKET_ERROR
        {
            return Err(format!(
                "SIO_RCVALL falhou (erro {}). Rode como Administrador.",
                WSAGetLastError().0
            ));
        }

        *status.lock().unwrap() = format!("capturando em {iface}");

        let start = Instant::now();
        let mut buf = [0u8; 65535];
        while shared.running.load(Ordering::Relaxed) {
            let n = recv(sock, &mut buf, SEND_RECV_FLAGS(0));
            if n == SOCKET_ERROR {
                let err = WSAGetLastError();
                if err == WSAETIMEDOUT {
                    continue; // so um tick para reavaliar o flag de parada
                }
                return Err(format!("recv falhou (erro {})", err.0));
            }
            if n <= 0 {
                continue;
            }
            let ms = start.elapsed().as_millis() as u64;
            ingest(iface, &buf[..n as usize], ms, shared);
        }
    }
    Ok(())
}

/// Dissecca um pacote IPv4 e atualiza os agregados.
fn ingest(iface: Ipv4Addr, pkt: &[u8], ms: u64, shared: &Arc<CaptureShared>) {
    if pkt.len() < 20 {
        return;
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return;
    }
    let proto = pkt[9];
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as u64;

    // portas para TCP (6) / UDP (17): primeiros 4 bytes do cabecalho L4
    let (mut src_port, mut dst_port) = (0u16, 0u16);
    if (proto == 6 || proto == 17) && pkt.len() >= ihl + 4 {
        src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    }

    // determina lado local vs remoto pela interface
    let (local_port, remote_ip, remote_port) = if src == iface {
        (src_port, dst, dst_port)
    } else if dst == iface {
        (dst_port, src, src_port)
    } else {
        // nem entrada nem saida pela nossa interface (broadcast/multicast)
        (src_port, dst, dst_port)
    };

    shared.total_packets.fetch_add(1, Ordering::Relaxed);
    shared.total_bytes.fetch_add(total_len, Ordering::Relaxed);

    let mut convs = shared.convs.lock().unwrap();
    if let Some(c) = convs.iter_mut().find(|c| {
        c.proto == proto
            && c.local_port == local_port
            && c.remote_ip == remote_ip
            && c.remote_port == remote_port
    }) {
        c.packets += 1;
        c.bytes += total_len;
        c.last_ms = ms;
    } else if convs.len() < MAX_CONVS {
        convs.push(Conversation {
            proto,
            local_port,
            remote_ip,
            remote_port,
            packets: 1,
            bytes: total_len,
            last_ms: ms,
        });
    }
}

/// Fecha o socket no fim do escopo.
struct SocketGuard(SOCKET);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = closesocket(self.0);
        }
    }
}

/// Chama WSACleanup no fim do escopo.
struct WsaCleanupGuard;
impl Drop for WsaCleanupGuard {
    fn drop(&mut self) {
        unsafe {
            WSACleanup();
        }
    }
}
