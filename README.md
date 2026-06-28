<img src="assets/quarry-256.png" alt="Quarry" width="128" align="right" />

# Quarry

**Ferramenta de análise de jogos e software, em Rust, com interface gráfica.**
Um "Burp Suite para software": scanner/editor de memória (estilo Cheat Engine)
na seção **General Exploring**, e um arsenal que **não toca no processo** — proxy
de interceptação HTTPS, captura passiva de rede (TCP/UDP), redirect de tráfego
por processo (WinDivert) e APIs locais da Riot (LCU) — na seção **Kernel
Exploring**, que funciona mesmo com anti-cheat kernel.

> ⚠️ **Uso responsável.** Esta ferramenta é para jogos **Que autorizam analise profunda**, seus
> próprios programas e estudo de engenharia reversa. **Não use o modo General Exploration em jogos online
> ou competitivos** com anti-cheat (BattlEye, EAC, VAC, etc.): além de violar os
> termos de uso e resultar em banimento, esses sistemas protegem o processo e
> podem travar a aplicação. Use por sua conta e risco.

---

## Recursos

| Aba | O que faz |
|-----|-----------|
| **Busca** | First/Next scan em thread de fundo (com barra de progresso e cancelar). Tipos `i8`–`u64`, `f32`, `f64` e **strings** (UTF-8/ASCII e UTF-16/Unicode). Comparações: valor exato, maior/menor, **entre (intervalo)**, mudou, não mudou, aumentou, diminuiu. **Scan de valor inicial desconhecido** (snapshot + filtragem por mudou/aumentou/…). Inteiros de 64 bits comparados com precisão total (sem perda de `f64`). |
| **Cheat Table** | Salva endereços, mostra o valor em tempo real, escreve e **congela** valores. **Salva/carrega em arquivo `.qct`** (endereços, ponteiros, freeze e script do Auto Assembler) e **importa tabelas `.CT` do Cheat Engine**. |
| **Pointer Scan** | Encontra cadeias de ponteiros estáveis (`["game.exe"+1A2B]+10+8`) que sempre levam ao endereço, mesmo após reiniciar o jogo — e as resolve dinamicamente. |
| **Memory Viewer** | Hex dump e **disassembly x86-64** ao vivo de qualquer endereço, com NOP/+tabela por instrução, e **"o que escreve/acessa este endereço"** (breakpoint de hardware via debugger) para achar a instrução que altera um valor. |
| **Auto Assembler** | Scripts estilo Cheat Engine (`[ENABLE]`/`[DISABLE]`): `aobscanmodule`, `alloc` de code cave perto do alvo, `label`, `db`, `jmp`/`call`/`jmp64`, **saltos condicionais** (`je`/`jne`/`jg`/…), `dq`/`dd`, `dealloc`. Monta mnemônicos x86-64 (mov/add/lea/`imul`/shifts/`movzx`/SSE) sem `db` cru. Aplica e desfaz patches. |
| **Injeção** | Lista módulos, AOB scan (com curinga `??`), patch de bytes, NOP e injeção de DLL (`LoadLibraryW` + `CreateRemoteThread`). |
| **Script** | Automação via **rhai** (Rust puro) em thread de fundo: `read_i32`/`read_f32`/`read_ptr`/`read_bytes`, `write_i32`/`write_bytes`, `module_base(nome)`, `aob_scan`/`aob_scan_module`, `print`. |
| **Unity/Mono** | Detecta o backend de scripting (Mono vs IL2CPP vs Unity) pelos módulos e lê a **API `mono_*`** direto do PE em memória (só leitura). |
| **Correlação** | Liga memória e rede: procura um **valor (ou bytes de um endereço)** no **tráfego capturado** por processo, sem hook nem injeção. |
| **Proxy HTTPS** *(Kernel Exploring)* | Proxy de interceptação com CA própria: **Histórico**, **Intercept** (pausar/editar/forward), **Repeater** e **Match & Replace**. Não toca no processo. Veja [Proxy HTTPS](#proxy-https-kernel-exploring). |
| **Captura passiva** *(Kernel Exploring)* | Sniffer por processo via raw socket (`SIO_RCVALL`): captura **TCP e UDP**, filtra por protocolo, disseca o cabeçalho L4 e **identifica o protocolo de aplicação** (DNS/QUIC/DTLS/STUN/RTP…). Tráfego de jogo é quase todo UDP. Estilo Wireshark, sem tocar no processo. |
| **Redirect (WinDivert)** *(Kernel Exploring)* | **Proxifier embutido**: força o TCP de saída de um processo pelo Quarry via WinDivert — **sem injetar no jogo**. Redireciona as conexões para um listener local que faz a ponte até o destino real e lê HTTP em texto puro. Requer `WinDivert.dll`/`.sys` + Admin. |
| **API Riot (LCU)** *(Kernel Exploring)* | APIs locais da Riot sem injeção: **Console** REST do League Client + **Riot Client** (cross-game VALORANT/LoR), **explorador de endpoints** (swagger), **feed de eventos** ao vivo (WebSocket WAMP), **dados de partida** (Live Client Data, porta 2999) e **recon de VDP** (CSRF/DNS-rebinding + auditoria de exposição de token). |

> O Quarry separa as funções em duas seções: **General Exploring** (acessa o
> processo: busca, pointer scan, assembler, injeção) e **Kernel Exploring** (não
> toca no processo: proxy HTTPS, captura passiva TCP/UDP, redirect por processo e
> APIs locais da Riot), com detecção de anti-cheat que bloqueia a injeção e roteia
> para a seção segura quando detecta um anti-cheat kernel.

## Por que pointer scan importa

O endereço de um valor (ex: a vida) muda toda vez que o jogo é reaberto. O que
**não** muda é o caminho de ponteiros, ancorado em um módulo do processo
(`game.exe`, uma DLL). O Quarry monta um mapa reverso de ponteiros e faz uma
busca a partir do alvo até encontrar uma âncora estática, gerando cadeias que
funcionam de forma confiável entre execuções.

## Requisitos

- Windows (x64)
- [Rust](https://www.rust-lang.org/tools/install) 1.82 ou superior

> A **busca de memória e o pointer scan** detectam a arquitetura do alvo
> (x64 ou 32-bit/WOW64) e usam ponteiros de 8 ou 4 bytes automaticamente. A
> **injeção de DLL e o Auto Assembler** ainda geram código **x64** — use-os
> apenas em alvos x64.

## Instalação (usuário final)

A forma mais simples é o **instalador**: um único `quarry-setup-<versão>.exe`, um
**assistente gráfico** (Bem-vindo → Licença → Opções → Instalar → Concluir) que
traz tudo embutido — o `quarry.exe`, o driver **WinDivert** (usado pela aba
[Redirect](#redirect-windivert-kernel-exploring)) e o ícone. Ele instala em
`Program Files`, cria atalho no **menu Iniciar** e (opcional) na **área de
trabalho**, e registra a desinstalação em *Aplicativos instalados*. Pede elevação
(UAC) por precisar de Administrador.

> O instalador é **auto-extraível e puro Rust** (sem Inno Setup, sem winget, sem
> nenhuma ferramenta externa): o próprio `quarry-setup.exe`, escrito com egui,
> embute os arquivos via `include_bytes!`. Para desinstalar, use *Aplicativos
> instalados* ou o atalho **Desinstalar Quarry**.

### Gerar o instalador

Único pré-requisito: [Rust](https://www.rust-lang.org/tools/install).

```powershell
git clone https://github.com/Poluxin21/quarry.git
cd quarry
# (opcional) regerar o ícone a partir do SVG — o .ico já vem versionado:
#   cargo run --manifest-path tools/iconize/Cargo.toml
# gera o instalador (compila release, baixa o WinDivert e empacota):
powershell -ExecutionPolicy Bypass -File installer\build-installer.ps1
```

O instalador sai em `dist\quarry-setup-<versão>.exe` — um único `.exe` para
distribuir.

## Compilar e rodar (desenvolvimento)

```powershell
cargo run --release
```

Use `--release` para que a varredura de memória fique muito mais rápida.

> Para anexar à maioria dos jogos é preciso rodar o Quarry **como
> Administrador**. O `.exe` de **release** já embute um manifesto que exige
> elevação; o build de **debug** não, para não disparar UAC a cada `cargo run`.
> Para a aba **Redirect** funcionar fora do instalador, coloque o `WinDivert.dll`
> e o `WinDivert64.sys` ao lado do executável.

## Como usar (exemplo rápido)

1. Clique em **Selecionar processo** e escolha o alvo (ou abra a Calculadora
   para testar sem jogo).
2. Na aba **Busca**, digite um valor que você vê na tela e clique **First Scan**.
3. Mude o valor no jogo, ajuste a comparação e clique **Next Scan** para
   restringir até sobrar o endereço certo.
4. Clique em **+ tabela** para salvá-lo. Na Cheat Table você pode **escrever** ou
   **congelar** o valor.
5. (Opcional) Clique em **pointer scan deste endereço** para achar uma cadeia
   estável e adicioná-la à tabela — assim o cheat continua funcionando depois de
   reabrir o jogo.

## Estrutura do projeto

```
src/
  main.rs      GUI (egui/eframe), cheat table e thread de freeze
  process.rs   enumerar e abrir processos
  memory.rs    ler/escrever memória e enumerar regiões
  value.rs     tipos de valor (parse/format)
  scan.rs      motor de busca (first/next scan, leitura em chunks)
  pointer.rs   pointer scanner (busca reversa de cadeias)
  table.rs     persistência da cheat table (.qct via serde)
  disasm.rs    disassembler x86-64 (Memory Viewer, sobre iced-x86)
  debugger.rs  "o que escreve aqui" (DebugActiveProcess + DR0–DR7)
  asm_x86.rs   montador de mnemônicos x86-64 (back-end do Auto Assembler)
  assembler.rs auto assembler (scripts de code cave / patch)
  inject.rs    módulos, AOB scan, patch/NOP, injeção de DLL
  anticheat.rs detecção de anti-cheat e roteamento Kernel/General
  proxy.rs     proxy HTTPS de interceptação (MITM com CA própria)
  capture.rs   captura passiva TCP+UDP por processo (RAW socket + IP Helper) com ID de protocolo
  redirect.rs  redirect transparente de TCP por processo via WinDivert (Proxifier embutido)
  hotkeys.rs   hotkeys globais (RegisterHotKey)
  lcu.rs       APIs locais da Riot: LCU + Riot Client + Live Client + swagger + auditoria VDP
  lcu_ws.rs    stream de eventos do LCU via WebSocket (WAMP)
  ce_import.rs import de tabelas .CT do Cheat Engine
  script.rs    camada de scripting/automação (motor rhai)
  unity.rs     dissector Unity/Mono/IL2CPP (detecção + exports da API mono)
build.rs       embute ícone (.ico) + manifesto de Admin (release) no exe
assets/        quarry.svg (fonte do ícone) + quarry.ico/quarry-256.png (gerados)
installer/setup/  instalador gráfico (wizard egui, auto-extraível, embute tudo)
installer/build-installer.ps1  builda o quarry, baixa o WinDivert e empacota
tools/iconize/ gerador do ícone (SVG → .ico/.png, resvg; projeto à parte)
```

## Auto Assembler

Exemplo de script (god mode trocando a instrução que tira vida por um code cave):

```
[ENABLE]
aobscanmodule(inject, jogo.exe, 89 83 A4 00 00 00)
alloc(newmem, 0x1000, inject)

newmem:
  db 89 83 A4 00 00 00   // instrução original
  jmp return

inject:
  jmp newmem
  nop                    // completa o tamanho da instrução original
return:

[DISABLE]
inject:
  db 89 83 A4 00 00 00   // restaura os bytes originais
dealloc(newmem)
```

Números: `0x..` ou `$..` = hex, sem prefixo = decimal. Para instruções que o
montador não gera, use `db` com os bytes crus.

## Proxy HTTPS (Kernel Exploring)

A seção **Kernel Exploring** traz um proxy de interceptação estilo Burp que
**não toca no processo** — funciona com qualquer alvo, inclusive sob anti-cheat
kernel. Ele intercepta apenas tráfego **HTTP(S)** (login, loja, matchmaking,
APIs); o tráfego de jogo em tempo real (UDP/binário próprio) não passa pelo
**proxy** — mas é capturado e dissecado pela **Captura passiva** (TCP **e** UDP),
que vê portas, volume, protocolo de aplicação e o payload (cifrado quando TLS/QUIC).

### 1. Iniciar o proxy

Aba **Proxy HTTPS** → defina a porta (padrão `8080`) → **Iniciar**. Na primeira
execução o Quarry gera, no diretório de trabalho:

- **`quarry-ca.pem`** — o certificado da CA (é este que você instala);
- **`quarry-ca.key.pem`** — a chave privada da CA (**mantenha em segredo, nunca
  compartilhe**: quem tiver ela consegue forjar HTTPS para quem confia na sua CA).

### 2. Instalar a CA (`quarry-ca.pem`)

Para ler HTTPS o proxy faz MITM: apresenta ao alvo um certificado *daquele host*
assinado pela sua CA. O cliente só aceita se **confiar na CA** — por isso a
instalação. Sem ela, o TLS quebra com erro de certificado.

```powershell
# Por usuário (não precisa de admin) — basta se o jogo roda com o seu usuário:
certutil -addstore -user Root quarry-ca.pem

# Para a máquina inteira (precisa de admin):
certutil -addstore Root quarry-ca.pem
```

Ou pela interface gráfica: renomeie para `quarry-ca.crt`, duplo-clique →
*Instalar Certificado* → *Autoridades de Certificação Raiz Confiáveis*.

Quando terminar, **remova a CA** (recomendado — é um root CA poderoso):

```powershell
certutil -delstore -user Root "Quarry Proxy CA"
```

### 3. Apontar o jogo para o proxy

O proxy escuta em `127.0.0.1:<porta>`. Para mirar **só um jogo/processo**:

| Método | Mira 1 processo? | Como |
|--------|------------------|------|
| **Redirect (WinDivert)** *(embutido)* | ✅ Sim (recomendado) | Aba **Redirect (WinDivert)**: informe o PID e o Quarry força o TCP daquele processo pelo listener local — sem app externo. Requer `WinDivert.dll`/`.sys` + Admin. Veja [Redirect](#redirect-windivert-kernel-exploring). |
| **Proxifier / ProxyCap** *(externo)* | ✅ Sim | Alternativa paga: regra `jogo.exe → proxy HTTP 127.0.0.1:8080`. Útil se você já usa ou se o WinDivert esbarrar no anticheat. |
| Proxy do sistema (Configurações → Rede → Proxy) | ❌ Pega tudo | Rápido para teste amplo, mas muitos jogos ignoram o proxy do sistema. |
| `HTTP_PROXY` / `HTTPS_PROXY` | ⚠️ Só se o app respeitar | Útil para launchers Chromium e SDKs; jogos raramente honram. |

Com a CA instalada e o tráfego apontado, o **Histórico** enche com as
requisições; ligue o **Intercept** para pausar/editar antes de enviar (botão
direito no *Forward* para interceptar também a resposta), use o **Repeater**
para reenviar requisições editadas, ou crie regras automáticas em
**Match & Replace**.

### Limitações

- **Certificate pinning**: vários jogos competitivos ignoram a trust store e só
  aceitam o próprio certificado — o MITM falha mesmo com a CA instalada.
- **Tráfego não-HTTP** (a maior parte do gameplay, em UDP) não passa por um proxy
  HTTP — para esse use a **Captura passiva**, que disseca TCP e UDP por processo.

## Redirect (WinDivert) — Kernel Exploring

A maioria dos jogos não tem configuração de proxy, então para mandar o tráfego
deles ao proxy do Quarry você precisaria de um **Proxifier** (pago) à parte. A
aba **Redirect (WinDivert)** embute isso: usando o driver do **WinDivert**, o
Quarry intercepta o **TCP de saída de um processo** (por PID) na pilha de rede —
**sem injetar no jogo** — redireciona para um listener local e faz a ponte até o
destino real, mantendo um *NAT map* para o caminho de volta. Pelo caminho, lê a
primeira linha de HTTP em texto puro.

Fluxo: informe o **PID** (botão "usar anexado" preenche com o processo anexado) e
a porta do listener → **Iniciar redirect**. As conexões redirecionadas aparecem
com destino original, volume ↑/↓ e a linha HTTP.

**Requisitos e limites:**

- **`WinDivert.dll` + `WinDivert64.sys`** ao lado do `quarry.exe` (não é
  dependência de build — a DLL é carregada em runtime; sem ela, só esta aba fica
  indisponível, com erro claro) e **privilégios de Administrador**.
- **Anticheat kernel** (Vanguard) pode **recusar o driver** no boot — aí funciona
  apenas em jogos sem AC kernel.
- **Certificate pinning** continua impedindo o MITM de HTTPS; o redirect entrega a
  conexão, mas o conteúdo TLS permanece cifrado. Ainda é útil para ver destinos,
  volume e o tráfego não-pinado/HTTP em claro.
- Hoje o listener faz **ponte transparente + leitura de HTTP**; plugar no MITM do
  proxy (decifrar HTTPS sem pinning) está no roadmap.

> ⚠ Experimental: a reescrita de pacote (NAT no kernel) segue o padrão do
> WinDivert mas precisa de validação na sua máquina (Admin + driver + tráfego
> real). Use só contra alvos próprios ou autorizados.

## API local da Riot (LCU) — Kernel Exploring

O League Client expõe uma API REST/WebSocket em `https://127.0.0.1:<porta>`,
autenticada por um token (`riot:<token>`) que fica em texto puro no **lockfile**
da pasta de instalação. O Quarry descobre porta e token pelo lockfile e conversa
com o client — **100% legítimo, sem injeção nem leitura de memória**, então
funciona mesmo com o Vanguard ativo. É uma bancada de recon do attack surface
local da Riot, pensada para pesquisa **autorizada** no programa de VDP/bug bounty.

Sub-abas (aba **API Riot (LCU)** na seção Kernel Exploring):

- **🖥 Console** — cliente REST genérico (método/path/body) com atalhos e
  visualização dos **headers** da resposta. Detecta também o **Riot Client**
  (lockfile próprio), que cobre conta, entitlements e o caminho para
  **VALORANT/LoR**.
- **📚 Endpoints** — puxa o `openapi.json` (swagger) do client e cataloga **toda**
  a superfície local: rota + método + descrição, com busca. Clique numa rota
  para carregá-la no Console. Recon de superfície num clique.
- **📡 Eventos (WS)** — assina `OnJsonApiEvent` por **WebSocket** (WAMP) e mostra,
  ao vivo, cada mudança de estado do client (fase de jogo, ready-check, champ
  select, lobby, loot…), com filtro. Ótimo para mapear fluxos e flagrar dados
  sensíveis cruzando a fronteira local.
- **🎯 Partida (2999)** — durante uma partida de LoL, lê a **Live Client Data
  API** (`https://127.0.0.1:2999/liveclientdata/*`): placar, itens, habilidades,
  ouro e eventos em tempo real. **Sem auth, sem lockfile, sem injeção** (cert
  público da Riot). Só responde com partida ativa.
- **🛡 Segurança (VDP)** — um **Request Lab estilo Repeater**: você controla
  **método, path, headers** (pode **forjar/sobrepor** `Origin`/`Host`/etc., com
  ou sem a auth do lockfile) e **body**, e vê a resposta **inteira** (status +
  todos os headers + body), com **veredito automático de CORS**. Atalhos prontos
  para forjar `Origin`/`Host` (CSRF/DNS-rebinding), montar um **preflight CORS**,
  e rodar a **auditoria de exposição de token** (mostra que qualquer processo
  local com o lockfile puxa tokens de auth e PII).

> ⚠ As ferramentas de VDP são para pesquisa **autorizada e dentro do escopo** do
> programa da Riot. Reporte os achados à Riot; não explore contas de terceiros.

## Memory Viewer e "o que escreve neste endereço"

A aba **Memory Viewer** (General Exploring) mostra, ao vivo, o **hex dump** e o
**disassembly x86-64** a partir de qualquer endereço (digite em hex e navegue com
`−80`/`+80`). No disassembly cada instrução tem botões **NOP** e **+tabela**.

O recurso **"o que escreve/acessa este endereço"** anexa o Quarry como *debugger*
ao alvo e arma um **breakpoint de hardware** (registradores DR0–DR7) no endereço.
Quando o jogo escreve ali, a instrução responsável (o `RIP`) aparece na lista com
a contagem de disparos — é assim que se descobre, por exemplo, a linha de código
que tira vida. Acione pelo botão **o que escreve** na Cheat Table ou no Memory
Viewer; marque **incluir leituras** para também capturar acessos de leitura.

> ⚠️ Anexar como debugger **pausa as threads brevemente e é detectável** por
> anticheat — por isso fica disponível só na seção **General Exploring** (alvos
> sem AC kernel). Há no máximo **4 breakpoints de hardware**; o Quarry usa o DR0.
> Fechar o Quarry **não** mata o alvo (`DebugSetProcessKillOnExit(false)`).

## Salvar/carregar a Cheat Table

Na Cheat Table, **💾 Salvar tabela** / **📂 Carregar tabela** gravam e leem um
arquivo **`.qct`** (JSON) com todas as entradas — endereços fixos, cadeias de
ponteiro, tipo, descrição, valor e estado de *freeze* — além do script atual do
Auto Assembler. Assim o trabalho sobrevive a reinícios do jogo e do Quarry.

## Roadmap

- [x] Salvar/carregar a cheat table em arquivo (`.qct`)
- [x] Memory Viewer com disassembly x86-64
- [x] "O que escreve/acessa este endereço" (breakpoints de hardware)
- [x] AOB scan em thread de fundo
- [x] Comparação por intervalo (entre X e Y) + precisão de inteiros 64-bit
- [x] Hotkeys globais (congelar tudo / Auto Assembler enable-disable)
- [x] Validação de pointer scan entre execuções
- [x] Scan de "valor inicial desconhecido"
- [x] Suporte a processos/ponteiros de 32-bit (busca e pointer scan; injeção/AA seguem x64)
- [x] Import de tabelas `.CT` do Cheat Engine
- [x] Camada de scripting (automação) — motor rhai com API de memória/AOB
- [x] Correlação memória ↔ rede (busca valores da memória no tráfego capturado)
- [x] APIs locais da Riot (LCU): Console REST + Riot Client cross-game (VALORANT/LoR)
- [x] Explorador de endpoints do LCU (catálogo via swagger/openapi)
- [x] Feed de eventos do LCU ao vivo (WebSocket WAMP / `OnJsonApiEvent`)
- [x] Live Client Data API in-game (porta 2999, dados de partida ao vivo)
- [x] Recon de VDP: teste de CSRF/DNS-rebinding + auditoria de exposição de token
- [x] Redirect transparente por processo (WinDivert) — Proxifier embutido, sem injeção
- [ ] Redirect: plugar no MITM do proxy (decifrar HTTPS sem pinning em modo transparente)
- [ ] VALORANT: APIs locais glz/pd/local via entitlements do Riot Client
- [ ] Hook inline de send/recv (interceptar a função no processo — injeção, detectável)
- [x] Dissector de Unity/Mono/.NET — detecção do backend + leitura da API `mono_*` (só leitura)
- [ ] Dissector: enumerar assemblies/classes/campos (requer chamar `mono_*` no alvo)
- [x] Montador de mnemônicos x86-64 (mov/add/lea/imul/shifts/movzx/SSE/jcc; `db` só para casos raros)

## Tecnologias

- [Rust](https://www.rust-lang.org/)
- [egui / eframe](https://github.com/emilk/egui) — interface gráfica
- [windows](https://github.com/microsoft/windows-rs) — WinAPI

## Licença

Source-available **proprietária** — o código é público para estudo, pesquisa de
segurança e contribuição, mas a propriedade do Quarry é do autor (modelo
semelhante ao Burp Suite). Veja [LICENSE](LICENSE). Uso somente contra alvos
próprios ou autorizados.
