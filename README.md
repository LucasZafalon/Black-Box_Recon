# BLACK BOX RECON

```
  ██████╗ ██╗      █████╗  ██████╗██╗  ██╗    ██████╗  ██████╗ ██╗  ██╗
  ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝    ██╔══██╗██╔═══██╗╚██╗██╔╝
  ██████╔╝██║     ███████║██║     █████╔╝     ██████╔╝██║   ██║ ╚███╔╝
  ██╔══██╗██║     ██╔══██║██║     ██╔═██╗     ██╔══██╗██║   ██║ ██╔██╗
  ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗    ██████╔╝╚██████╔╝██╔╝ ██╗
  ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
```

**Offensive Reconnaissance & Enumeration Framework — v4.0**  
*For authorized penetration testing only.*

**Autor:** Lucas Zafalon

**Propósito:** Ser a framework que eu queria ter tido quando comecei a fazer recon sério.

---

## Visão Geral

**Black Box Recon** é um framework de reconhecimento e enumeração ofensivo desenvolvido para operações de pentest em modalidade Black Box. O script automatiza as fases de Coleta de Informações, Varredura e Enumeração e Análise de Vulnerabilidades, orquestrando mais de 20 ferramentas especializadas em um pipeline coerente, com filtragem inteligente entre as fases e saída orientada a achados operacionais.

O objetivo não é substituir o analista — é eliminar o trabalho mecânico repetitivo e deixar o operador focado nos findings que realmente importam.

---

## Filosofia

- **Menos ruído, mais sinal.** Cada fase filtra o output antes de passá-lo para a próxima.
- **Transparência de execução.** O comando exato sendo rodado aparece no terminal antes de cada ferramenta.
- **Findings primeiro.** Vulnerabilidades críticas interrompem o fluxo visual com destaque máximo — não ficam escondidas no meio do output.
- **Graceful degradation.** Ferramentas ausentes são ignoradas com aviso; o script nunca aborta por dependência opcional faltando.
- **Arquivos com propósito.** Nenhum arquivo temporário ou output duplicado — cada arquivo gerado é usado em fases posteriores ou entregável final.

---

## Funcionalidades

| Capacidade | Ferramentas |
|---|---|
| WHOIS + DNS completo | `whois`, `dig` |
| Zone Transfer (AXFR) | `dig` |
| OSINT passivo | `theHarvester`, `crt.sh` |
| Enumeração de subdomínios | `subfinder`, `findomain`, `amass` |
| HTTP probe + fingerprint | `httpx`, `curl` |
| WAF detection | `wafw00f` |
| Fingerprint de tecnologias | `whatweb` |
| Port scanning | `nmap` |
| Análise SSL/TLS | `sslscan`, `openssl` |
| Directory brute force | `feroxbuster`, `gobuster`, `ffuf` |
| URL collection histórica | `gau`, `waybackurls`, `katana`, `hakrawler` |
| JS secret extraction | `curl` + regex patterns |
| Subdomain takeover | `subzy` |
| Vulnerability scanning | `nuclei` |
| Web audit | `nikto` |

---

## Fases do Fluxo

```
PHASE  0 — Dependency Check
PHASE  1 — WHOIS + DNS Records (+ AXFR attempt)
PHASE  2 — Passive OSINT (theHarvester + crt.sh)
PHASE  3 — Subdomain Enumeration + Smart Filtering
PHASE  4 — WAF Detection
PHASE  5 — Fingerprinting (WhatWeb + Security Headers)
PHASE  6 — Port Scanning (nmap top1000 + critical ports)
PHASE  7 — SSL/TLS Analysis
PHASE  8 — Directory Enumeration (wildcard detection + brute force)
PHASE  9 — URL Collection (Wayback + crawl ativo)
PHASE 10 — JS Analysis + Secret Extraction
PHASE 11 — Subdomain Takeover Check
PHASE 12 — Vulnerability Scan (nuclei)
PHASE 13 — Web Audit (nikto)
SUMMARY  — Relatório operacional final
```

---

## Dependências

### Obrigatórias

```bash
sudo apt install dnsutils whois curl
```

### Opcionais por categoria

**Enumeração de subdomínios**
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo apt install findomain amass
```

**HTTP probe e fingerprint**
```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo apt install whatweb
pip install wafw00f --break-system-packages
```

**Port scan e SSL**
```bash
sudo apt install nmap sslscan
```

**Directory brute force**
```bash
sudo apt install gobuster feroxbuster ffuf
```

**URL collection**
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hakluke/hakrawler@latest
```

**Vulnerability scanning**
```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo apt install nikto
```

**Takeover**
```bash
go install github.com/PentestPad/subzy@latest
```

**OSINT**
```bash
sudo apt install theHarvester
# Alternativa via uv:
pip install uv --break-system-packages
# uv run theHarvester (detectado automaticamente pelo script)
```

**Utilitários**
```bash
sudo apt install jq
```

> O arquivo `tools/INSTALL.md` gerado automaticamente pelo script contém todos esses comandos em um só lugar.

---

## Instalação

```bash
git clone https://github.com/seu-usuario/blackbox-recon.git
cd blackbox-recon
chmod +x recon.sh
```

Não requer instalação adicional. O script cria sua estrutura de diretórios na primeira execução.

---

## Uso

### Interativo
```bash
./recon.sh
# Solicita o domínio alvo no terminal
```

### Com flags
```bash
# Alvo via argumento
./recon.sh -d target.com

# Pular todas as confirmações de fase (modo automático)
./recon.sh -d target.com -y

# Executar apenas uma fase específica
./recon.sh -d target.com -p 3

# Exibir ajuda
./recon.sh -h
```

### Flags disponíveis

| Flag | Descrição |
|---|---|
| `-d DOMAIN` | Domínio alvo |
| `-y` | Pular confirmações (execução completa sem interação) |
| `-p N` | Executar apenas a fase N (1–13) |
| `-h` | Exibir ajuda |

---

## Estrutura de Diretórios

Após a primeira execução contra `target.com`, a estrutura criada é:

```
.
├── recon.sh
│
├── target.com/                   ← todos os resultados da operação
│   ├── recon.log                 ← log timestampado de toda a execução
│   ├── whois_dns.txt             ← WHOIS filtrado + todos os registros DNS
│   ├── emails.txt                ← emails únicos coletados (WHOIS + OSINT)
│   ├── crtsh.txt                 ← subdomínios via Certificate Transparency
│   ├── subdomains_raw.txt        ← todos os subdomínios encontrados (deduplicados)
│   ├── subdomains_alive.txt      ← hosts com HTTP/S ativo (httpx output)
│   ├── subdomains_interesting.txt ← painéis admin, serviços críticos
│   ├── unique_ips.txt            ← IPs únicos resolvidos
│   ├── waf.txt                   ← resultado WAF por host
│   ├── fingerprint.txt           ← WhatWeb output
│   ├── headers.txt               ← security headers por host
│   ├── nmap.txt                  ← scan top 1000 portas
│   ├── nmap_critical.txt         ← scan portas críticas com scripts auth
│   ├── ssl.txt                   ← análise TLS por host
│   ├── gobuster.txt              ← enumeração de diretórios
│   ├── urls_final.txt            ← URLs coletadas e classificadas
│   ├── js_secrets.txt            ← secrets encontrados em arquivos JS
│   ├── takeover_findings.txt     ← possíveis subdomain takeovers
│   ├── nuclei_findings.txt       ← findings do nuclei por severidade
│   └── nikto.txt                 ← auditoria nikto nos hosts prioritários
│
├── wordlists/                    ← wordlists utilizadas nas fases de brute force
│   └── common.txt                ← baixada automaticamente se nenhuma for encontrada
│
└── tools/
    └── INSTALL.md                ← comandos de instalação de todas as dependências
```

---

## Exemplo de Saída

### Tool box (antes de cada ferramenta)
```
 ┌──────────────────────────────────────────────────────┐
 │  TOOL   subfinder                                      │
 │  TARGET target.com                                     │
 │  ACTION Passive subdomain discovery                    │
 │  CMD    subfinder -d target.com -silent                │
 │  STATUS RUNNING ...                                    │
 └──────────────────────────────────────────────────────┘
```

### Porta crítica aberta
```
  ◉ CRITICAL PORT
  HOST : db01.target.com
  IP   : 10.0.0.5
  PORT : 3306/tcp
  INFO : MySQL 5.7.44
```

### Finding de vulnerabilidade
```
 ████████████████████████████████████████████████████████████
 ◉◉◉ CRITICAL FINDING  default-login em admin.target.com
 ████████████████████████████████████████████████████████████
```

### Summary final
```
 ══════════════════════════════════════════════════════════
 ▶▶  OPERATIONAL SUMMARY — target.com

  Subdomínios brutos:        87
  Hosts vivos:               43
  IPs únicos:                12
  URLs coletadas:          4821
  Emails coletados:           9
  Tempo total:             8m32s

  CRITICAL FINDINGS
  ◉ ZONE TRANSFER POSSÍVEL — infraestrutura interna exposta
  ◉ SECRETS EXPOSTOS EM JAVASCRIPT
  ◉ SUBDOMAIN TAKEOVER CONFIRMADO

  HIGH / MEDIUM FINDINGS
  ▲ PAINÉIS ADMINISTRATIVOS EXPOSTOS (3)
  ▲ PROTOCOLO TLS INSEGURO DETECTADO
```

---

## Filtragem Inteligente

A Phase 3 aplica um pipeline de filtragem progressiva antes de passar hosts para as fases seguintes:

```
subdomains_raw.txt
    │
    ▼ dig A record
    │  Remove N/A (sem resolução DNS)
    ▼
    │ httpx probe (HTTP/S)
    │  Remove hosts sem resposta
    ▼
subdomains_alive.txt
    │
    ▼ keyword match (admin|panel|login|...)
    │
subdomains_interesting.txt   ← prioridade em nikto, nuclei
```

A Phase 8 (directory enum) aplica validação adicional de wildcard antes de iniciar o brute force: envia uma requisição para um path aleatório e, se o servidor retornar 200, o host é marcado como wildcard e ignorado — evitando milhares de falsos positivos.

---

## Classificação de Severidade

| Nível | Cor | Exemplos |
|---|---|---|
| CRITICAL | Vermelho (blink) | Zone Transfer, Takeover, Nuclei critical, JS secrets, portas 3306/6379/27017 abertas |
| HIGH | Vermelho | Nuclei high, painéis admin expostos |
| MEDIUM / ATTENTION | Amarelo | WAF detectado, TLS 1.1, headers ausentes, nikto findings |
| INFORMATIONAL | Ciano | Emails coletados, API endpoints, tecnologias detectadas |

### SSL/TLS — distinção importante

O script **não** trata ausência de TLS 1.0/1.1 como problema. O comportamento correto moderno é exatamente não ter esses protocolos habilitados. Apenas os seguintes casos geram alertas reais:

- **CRÍTICO**: SSLv2, SSLv3, TLS 1.0 *habilitado*, RC4, NULL, ciphers EXPORT
- **ATENÇÃO**: TLS 1.1 habilitado (deprecado por RFC 8996), certificado expirando em menos de 30 dias
- **INFORMATIVO**: TLS 1.2/1.3 habilitado (comportamento esperado)

---

## Boas Práticas Operacionais

- Execute sempre com autorização formal documentada (contrato, escopo, ROE).
- Use `-p N` para reexecutar fases individuais sem refazer todo o recon.
- Em ambientes com WAF detectado, considere ajustar threads e timeouts nas ferramentas manualmente.
- Após a execução, o `recon.log` contém timestamps de cada fase — útil para correlacionar com logs do alvo durante o relatório.
- Para alvos grandes (+500 subdomínios), considere rodar as fases 8, 12 e 13 separadamente via `-p` para controle granular.
- O `nuclei` e o `nikto` são as fases mais ruidosas — em ambientes com IDS/IPS, avaliar execução fora do horário de monitoramento ativo.

---

## Roadmap Futuro

- [ ] Suporte a múltiplos alvos via arquivo (`-l targets.txt`)
- [ ] Modo stealth com throttling configurável por fase
- [ ] Integração com Burp Suite (exportar alive.txt como scope)
- [ ] Geração automática de relatório HTML/PDF ao final
- [ ] Suporte a autenticação para fases de brute force (cookies, tokens)
- [ ] Detecção de S3 buckets e cloud storage mal configurados
- [ ] Integração com Slack/Discord para notificação de findings críticos em tempo real
- [ ] Suporte a IPv6

---

## Disclaimer Legal

> **Este software é destinado exclusivamente a profissionais de segurança realizando testes autorizados.**
>
> O uso desta ferramenta contra sistemas sem autorização explícita e documentada é ilegal e sujeito a penalidades criminais nos termos da Lei 12.737/2012 (Lei Carolina Dieckmann), do Marco Civil da Internet (Lei 12.965/2014) e legislações equivalentes em outras jurisdições.
>
> Os autores não se responsabilizam por qualquer uso indevido, dano direto ou indireto causado pela utilização desta ferramenta fora do contexto de pentest contratado e autorizado.
>
> **Sempre obtenha autorização por escrito antes de executar qualquer teste.**

---

*Black Box Recon v4.0 — Built for operators, by operators.*
