#!/usr/bin/env bash
# ==============================================================================
#  BLACK BOX RECON v4.0
#  Offensive Reconnaissance & Enumeration Framework
#  Authorized Penetration Testing Only
# ==============================================================================
#
#  Estrutura de fases:
#   PHASE  1 — WHOIS + DNS Records
#   PHASE  2 — Passive OSINT (theHarvester + crt.sh)
#   PHASE  3 — Subdomain Enumeration + Filtragem Inteligente
#   PHASE  4 — WAF Detection
#   PHASE  5 — Fingerprinting (WhatWeb + Headers)
#   PHASE  6 — Port Scanning (nmap)
#   PHASE  7 — SSL/TLS Analysis
#   PHASE  8 — Directory Enumeration (gobuster/feroxbuster)
#   PHASE  9 — URL Collection (gau/waybackurls/katana)
#   PHASE 10 — JS Analysis + Secret Extraction
#   PHASE 11 — Subdomain Takeover Check
#   PHASE 12 — Vulnerability Scan (nuclei)
#   PHASE 13 — Web Audit (nikto)
#   SUMMARY  — Relatório operacional final
#
#  Arquivos gerados (apenas os úteis):
#   {target}/subdomains_raw.txt        → todos os subdomínios encontrados
#   {target}/subdomains_alive.txt      → subdomínios com HTTP ativo
#   {target}/subdomains_interesting.txt → painéis, serviços críticos
#   {target}/unique_ips.txt            → IPs únicos resolvidos
#   {target}/emails.txt                → emails coletados passivamente
#   {target}/waf.txt                   → resultado WAF por host
#   {target}/nmap.txt                  → scan de portas
#   {target}/ssl.txt                   → análise TLS
#   {target}/gobuster.txt              → enumeração de diretórios
#   {target}/urls_final.txt            → URLs coletadas e classificadas
#   {target}/js_secrets.txt            → secrets encontrados em JS
#   {target}/takeover_findings.txt     → possíveis takeovers
#   {target}/nuclei_findings.txt       → findings do nuclei
#   {target}/nikto.txt                 → auditoria nikto
#   {target}/recon.log                 → log timestampado da operação
# ==============================================================================

# Não usa -e: grep sem match retorna exit 1 e abortaria o script
set -uo pipefail
IFS=$'\n\t'

# Expande PATH para ferramentas Go (~/.go/bin), pip (~/.local/bin) e Cargo
export PATH="${PATH}:${HOME}/go/bin:${HOME}/.local/bin:${HOME}/.cargo/bin:/usr/local/go/bin"

# ==============================================================================
#  CORES E ESTILO
# ==============================================================================
R='\033[0;31m'       # Vermelho
G='\033[0;32m'       # Verde
Y='\033[1;33m'       # Amarelo bold
C='\033[0;36m'       # Ciano
M='\033[0;35m'       # Magenta
W='\033[1;37m'       # Branco bold
DIM='\033[2m'        # Escurecido
BOLD='\033[1m'
BLINK='\033[5m'
BG_R='\033[41m'      # Background vermelho
BG_Y='\033[43m'      # Background amarelo
RESET='\033[0m'

# ==============================================================================
#  VARIÁVEIS GLOBAIS
# ==============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET=""            # Domínio alvo sanitizado
BASE_DIR=""          # {SCRIPT_DIR}/{TARGET}/ — pasta de resultados
WL_DIR="${SCRIPT_DIR}/wordlists"    # Pasta de wordlists
TOOLS_DIR="${SCRIPT_DIR}/tools"     # Pasta de ferramentas extras
START_TS=0           # Timestamp de início para cálculo de elapsed
SKIP_CONFIRM=0       # Flag -y: pula todas as confirmações
PHASE_ONLY=""        # Flag -p N: executa apenas uma fase

# Arrays populados durante execução e reutilizados nas fases seguintes
ALIVE_HOSTS=()       # URLs vivas com HTTP ativo (https://sub.target.com)
UNIQUE_IPS=()        # IPs únicos resolvidos

# Códigos HTTP que indicam descobertas reais em directory brute force
PENTEST_CODES="200,204,301,302,307,308,401,403,405,500,503"

# Wordlist ativa para gobuster/feroxbuster (resolvida em _setup_dirs)
WL_DIRS=""

# Contadores globais para o summary final
COUNT_EMAILS=0
COUNT_SUBDOMAINS=0
COUNT_ALIVE=0
COUNT_IPS=0
COUNT_URLS=0
COUNT_SECRETS=0
COUNT_NUCLEI_CRIT=0
COUNT_NUCLEI_HIGH=0
PANELS_FOUND=()      # Painéis admin detectados
CRIT_PORTS_FOUND=()  # Portas críticas encontradas abertas
WAFS_FOUND=()        # WAFs detectados por host

# ==============================================================================
#  FUNÇÕES DE OUTPUT
# ==============================================================================

# Separador simples
_sep()  { printf "${DIM}%s${RESET}\n" "$(printf '─%.0s' {1..78})"; }

# Separador duplo
_sep2() { printf "${DIM}%s${RESET}\n" "$(printf '═%.0s' {1..78})"; }

# Informação geral [*]
_info() { printf " ${C}[*]${RESET} %b\n" "$*"; }

# Sucesso / resultado positivo [+]
_ok()   { printf " ${G}[+]${RESET} %b\n" "$*"; }

# Aviso operacional [!]
_warn() { printf " ${Y}[!]${RESET} %b\n" "$*"; }

# Erro fatal [✗]
_err()  { printf " ${BOLD}${R}[✗]${RESET} %b\n" "$*" >&2; }

# Item ignorado / tool ausente [-]
_skip() { printf " ${DIM}[-] %b${RESET}\n" "$*"; }

# Achado operacional relevante — caixa destacada em verde
_find() {
    local msg="$*"
    local line; line=$(printf '─%.0s' {1..58})
    echo
    printf " ${BOLD}${G}┌${line}┐${RESET}\n"
    printf " ${BOLD}${G}│${RESET}  ${BOLD}◈ FIND${RESET}  %-50s ${BOLD}${G}│${RESET}\n" "${msg:0:50}"
    printf " ${BOLD}${G}└${line}┘${RESET}\n"
    echo
}

# Vulnerabilidade / finding crítico — máximo destaque, bloco vermelho
_crit() {
    local msg="$*"
    echo
    printf " ${BOLD}${BG_R}                                                              ${RESET}\n"
    printf " ${BOLD}${BG_R}  ${BLINK}◉◉◉${RESET}${BOLD}${BG_R} CRITICAL FINDING %-38s${RESET}\n" "${msg:0:38}"
    printf " ${BOLD}${BG_R}                                                              ${RESET}\n"
    echo
}

# Aviso de segurança — destaque médio, amarelo
_vuln_warn() {
    local msg="$*"
    echo
    printf " ${BOLD}${Y}  ▲  SECURITY ISSUE: %b${RESET}\n" "$msg"
    echo
}

# Nota informativa de segurança — sem alarme
_note() {
    printf " ${DIM}  ℹ  %b${RESET}\n" "$*"
}

# Cabeçalho de fase
_phase() {
    echo
    _sep2
    printf " ${BOLD}${M}▶  PHASE %-2s — %s${RESET}\n" "$1" "$2"
    _sep2
    echo
}

# Bloco visual antes de executar uma ferramenta — mostra contexto da execução
# Uso: _tool_box "TOOL_NAME" "TARGET" "AÇÃO" "COMANDO"
_tool_box() {
    local tool="$1"
    local target="$2"
    local action="$3"
    local cmd="$4"
    local line; line=$(printf '─%.0s' {1..54})
    printf "\n ${BOLD}${C}┌${line}┐${RESET}\n"
    printf " ${BOLD}${C}│${RESET}  ${DIM}TOOL  ${RESET} ${BOLD}%-46s${RESET} ${BOLD}${C}│${RESET}\n" "$tool"
    printf " ${BOLD}${C}│${RESET}  ${DIM}TARGET${RESET} ${C}%-46s${RESET} ${BOLD}${C}│${RESET}\n" "${target:0:46}"
    printf " ${BOLD}${C}│${RESET}  ${DIM}ACTION${RESET} %-46s ${BOLD}${C}│${RESET}\n" "${action:0:46}"
    printf " ${BOLD}${C}│${RESET}  ${DIM}CMD   ${RESET} ${DIM}%-46s${RESET} ${BOLD}${C}│${RESET}\n" "${cmd:0:46}"
    printf " ${BOLD}${C}│${RESET}  ${G}STATUS${RESET} ${BOLD}${G}RUNNING ...${RESET}%-37s ${BOLD}${C}│${RESET}\n" ""
    printf " ${BOLD}${C}└${line}┘${RESET}\n\n"
}

# Resultado resumido após execução de uma tool
_tool_result() {
    local tool="$1"; local result="$2"
    printf " ${G}[+]${RESET} ${BOLD}%-14s${RESET} %b\n" "${tool}:" "$result"
}

# Elapsed time desde START_TS
_elapsed() {
    local s=$(( $(date +%s) - START_TS ))
    printf "%dm%02ds" $(( s/60 )) $(( s%60 ))
}

# Log timestampado para arquivo
_log() {
    [[ -n "${BASE_DIR:-}" ]] && \
        echo "[$(date '+%H:%M:%S')] $*" >> "${BASE_DIR}/recon.log" 2>/dev/null || true
}

# ==============================================================================
#  DETECÇÃO DE FERRAMENTAS
# ==============================================================================

# _has: verifica se tool existe no PATH expandido ou em caminhos alternativos.
# Resolve problema de Go tools (nuclei, httpx) em ~/go/bin e Python tools
# (wafw00f, whatweb) em ~/.local/bin não serem detectadas pelo command -v padrão.
_has() {
    local t="$1"
    command -v "$t" &>/dev/null && return 0
    for p in \
        "${HOME}/.local/bin/${t}" \
        "${HOME}/go/bin/${t}" \
        "${GOPATH:-${HOME}/go}/bin/${t}" \
        "${HOME}/.cargo/bin/${t}" \
        "/usr/local/bin/${t}" \
        "${TOOLS_DIR}/${t}"; do
        [[ -x "$p" ]] && return 0
    done
    return 1
}

# _which: retorna o caminho real da ferramenta
_which() {
    local t="$1"
    command -v "$t" 2>/dev/null && return 0
    for p in \
        "${HOME}/.local/bin/${t}" \
        "${HOME}/go/bin/${t}" \
        "${GOPATH:-${HOME}/go}/bin/${t}" \
        "${HOME}/.cargo/bin/${t}" \
        "/usr/local/bin/${t}" \
        "${TOOLS_DIR}/${t}"; do
        [[ -x "$p" ]] && echo "$p" && return 0
    done
    return 1
}

# theHarvester: suporta chamada direta ou via "uv run theHarvester"
_has_harvester() { _has theHarvester || _has uv; }
_run_harvester()  {
    if _has theHarvester; then
        "$(_which theHarvester 2>/dev/null || echo theHarvester)" "$@"
    else
        uv run theHarvester "$@"
    fi
}

# ==============================================================================
#  CONFIRMAÇÃO DE FASE
# ==============================================================================
_confirm_phase() {
    [[ "$SKIP_CONFIRM" -eq 1 ]] && return 0
    [[ -n "$PHASE_ONLY"  ]] && return 0
    echo
    printf " ${C}[?]${RESET} Executar ${BOLD}%s${RESET}? [${G}Y${RESET}/${R}n${RESET}/${Y}s${RESET}=skip all] " "$1"
    read -r ans || ans="y"
    case "${ans,,}" in
        n) return 1 ;;
        s) SKIP_CONFIRM=1; return 0 ;;
        *) return 0 ;;
    esac
}

# ==============================================================================
#  BANNER
# ==============================================================================
_banner() {
    clear
    printf "${R}"
    cat << 'BANNER'

  ██████╗ ██╗      █████╗  ██████╗██╗  ██╗    ██████╗  ██████╗ ██╗  ██╗
  ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝    ██╔══██╗██╔═══██╗╚██╗██╔╝
  ██████╔╝██║     ███████║██║     █████╔╝     ██████╔╝██║   ██║ ╚███╔╝
  ██╔══██╗██║     ██╔══██║██║     ██╔═██╗     ██╔══██╗██║   ██║ ██╔██╗
  ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗    ██████╔╝╚██████╔╝██╔╝ ██╗
  ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝

BANNER
    printf "${RESET}"
    printf "${DIM}  Black Box Reconnaissance & Enumeration Framework — v4.0${RESET}\n"
    printf "${DIM}  For authorized penetration testing only.${RESET}\n\n"
    _sep2
    printf "  ${DIM}%-16s${RESET}  ${W}%s${RESET}\n" "Date"     "$(date '+%Y-%m-%d %H:%M:%S')"
    printf "  ${DIM}%-16s${RESET}  ${W}%s${RESET}\n" "Operator" "$(whoami)@$(hostname 2>/dev/null || echo local)"
    printf "  ${DIM}%-16s${RESET}  ${W}%s${RESET}\n" "Shell"    "${SHELL:-bash}"
    _sep2
    echo
}

# ==============================================================================
#  VERIFICAÇÃO DE DEPENDÊNCIAS
# ==============================================================================
_check_deps() {
    _phase "0" "DEPENDENCY CHECK"

    # Ferramentas obrigatórias — sem elas o script não funciona
    local required=(dig host whois curl)

    # Ferramentas opcionais — cada fase verifica e adapta
    local optional=(
        subfinder findomain amass
        httpx dnsx
        wafw00f whatweb
        nmap sslscan
        gobuster feroxbuster ffuf
        nuclei nikto
        gau waybackurls katana hakrawler
        subzy jq
    )

    printf "  ${BOLD}%-22s  %-16s  %s${RESET}\n" "FERRAMENTA" "STATUS" "TIPO"
    _sep

    local missing_req=()
    for t in "${required[@]}"; do
        if _has "$t"; then
            printf "  ${G}%-22s  ✔ encontrada     obrigatória${RESET}\n" "$t"
        else
            printf "  ${R}%-22s  ✗ AUSENTE        obrigatória${RESET}\n" "$t"
            missing_req+=("$t")
        fi
    done

    # theHarvester: pode estar diretamente no PATH ou acessível via "uv run"
    if _has theHarvester; then
        printf "  ${G}%-22s  ✔ encontrada     opcional${RESET}\n"   "theHarvester"
    elif _has uv; then
        printf "  ${G}%-22s  ✔ via uv run     opcional${RESET}\n"   "theHarvester"
    else
        printf "  ${Y}%-22s  - ausente        opcional${RESET}\n"   "theHarvester"
    fi

    local missing_opt=()
    for t in "${optional[@]}"; do
        if _has "$t"; then
            printf "  ${G}%-22s  ✔ encontrada     opcional${RESET}\n" "$t"
        else
            printf "  ${Y}%-22s  - ausente        opcional${RESET}\n" "$t"
            missing_opt+=("$t")
        fi
    done

    echo
    if [[ ${#missing_req[@]} -gt 0 ]]; then
        _err "Ferramentas obrigatórias ausentes: ${missing_req[*]}"
        _err "Instale: sudo apt install dnsutils whois curl"
        exit 1
    fi
    [[ ${#missing_opt[@]} -gt 0 ]] && \
        _warn "${#missing_opt[@]} opcional(is) ausente(s) — fases correspondentes serão ignoradas."
    _ok "Verificação de dependências concluída."
}

# ==============================================================================
#  ESTRUTURA DE DIRETÓRIOS
#  Apenas 3 pastas no nível do script:
#    {target}/     → resultados (arquivos flat, sem subpastas)
#    wordlists/    → wordlists usadas nas fases de brute force
#    tools/        → ferramentas customizadas + INSTALL.md
# ==============================================================================
_setup_dirs() {
    BASE_DIR="${SCRIPT_DIR}/${TARGET}"
    WL_DIR="${SCRIPT_DIR}/wordlists"
    TOOLS_DIR="${SCRIPT_DIR}/tools"

    mkdir -p "$BASE_DIR" "$WL_DIR" "$TOOLS_DIR"

    # Gera arquivo de instalação de dependências na pasta tools/
    cat > "${TOOLS_DIR}/INSTALL.md" << 'INSTALL'
# Instalação de dependências opcionais

## Ferramentas Go (requer: sudo apt install golang-go)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/PentestPad/subzy@latest

## Ferramentas apt
sudo apt install -y amass gobuster feroxbuster ffuf nikto sslscan nmap findomain

## Ferramentas Python
pip install wafw00f --break-system-packages
sudo apt install whatweb theHarvester
# Alternativa: pip install uv; uv run theHarvester
INSTALL

    # Resolve a melhor wordlist disponível para directory brute force
    WL_DIRS=""
    for wl in \
        "${WL_DIR}/common.txt" \
        "/usr/share/wordlists/dirb/common.txt" \
        "/usr/share/seclists/Discovery/Web-Content/common.txt" \
        "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt"; do
        [[ -f "$wl" ]] && WL_DIRS="$wl" && break
    done

    # Tenta baixar common.txt do SecLists se nenhuma foi encontrada
    if [[ -z "$WL_DIRS" ]]; then
        _info "Wordlist não encontrada. Baixando common.txt do SecLists..."
        curl -sf --max-time 30 \
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
            -o "${WL_DIR}/common.txt" 2>/dev/null \
            && WL_DIRS="${WL_DIR}/common.txt" \
            && _ok "Wordlist baixada → ${WL_DIR}/common.txt" \
            || _warn "Falha ao baixar wordlist. Enumeração de diretórios pode falhar."
    fi

    echo
    _ok "Resultados  → ${BOLD}${BASE_DIR}/${RESET}"
    _ok "Wordlists   → ${BOLD}${WL_DIR}/${RESET}"
    _ok "Tools       → ${BOLD}${TOOLS_DIR}/${RESET}"
    [[ -n "$WL_DIRS" ]] && _ok "Wordlist    → ${BOLD}${WL_DIRS}${RESET} ($(wc -l < "$WL_DIRS") entradas)"
}

# ==============================================================================
#  PHASE 1 — WHOIS + DNS RECORDS
#  Coleta informações de registro do domínio e enumeração DNS completa.
#  Tenta Zone Transfer (AXFR) em todos os nameservers encontrados.
#  Extrai emails, IPs do SPF, nomes de organizações para uso posterior.
# ==============================================================================
phase_whois_dns() {
    _phase "1" "WHOIS + DNS RECORDS"
    _confirm_phase "WHOIS + DNS" || { _skip "Fase ignorada pelo operador."; return; }

    local out="${BASE_DIR}/whois_dns.txt"
    echo "# WHOIS + DNS — ${TARGET} — $(date)" > "$out"

    # ── WHOIS ──────────────────────────────────────────────────────────────────
    _tool_box "whois" "$TARGET" "Coleta de dados de registro do domínio" "whois ${TARGET}"

    local whois_raw
    whois_raw=$(whois "$TARGET" 2>/dev/null || true)

    # Filtra apenas campos relevantes — evita o dump bruto do WHOIS
    local whois_clean
    whois_clean=$(echo "$whois_raw" \
        | grep -iE '^\s*(registrant|admin|tech|registrar|creation|expir|name.?server|status|abuse|org|email|country|owner|nic-hdl|person)\s*:' \
        | grep -v '^%' | sort -u || true)

    if [[ -n "$whois_clean" ]]; then
        echo "$whois_clean" | sed 's/^/  /'
        echo "$whois_clean" >> "$out"
    else
        _skip "WHOIS sem dados estruturados legíveis."
    fi

    # Extrai emails do WHOIS para lista de recon passivo
    local emails
    emails=$(echo "$whois_raw" \
        | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
        | sort -u || true)
    if [[ -n "$emails" ]]; then
        echo "$emails" > "${BASE_DIR}/emails.txt"
        _find "Emails no WHOIS:"
        echo "$emails" | sed 's/^/    /'
    fi

    echo >> "$out"
    echo

    # ── DNS RECORDS ────────────────────────────────────────────────────────────
    _tool_box "dig" "$TARGET" "Enumeração completa de registros DNS" "dig +short TYPE TARGET"

    local types=(A AAAA MX NS TXT SOA CAA)
    for t in "${types[@]}"; do
        local result
        result=$(dig +short "$TARGET" "$t" 2>/dev/null | head -20 || true)
        [[ -z "$result" ]] && continue

        printf "  ${BOLD}${C}%-8s${RESET}\n" "$t"
        echo "$result" | while IFS= read -r line; do
            printf "    ${W}%s${RESET}\n" "$line"
        done
        echo "${t}: ${result}" >> "$out"

        case "$t" in
            MX)
                _note "MX detectado → útil para theHarvester e caça de emails"
                ;;
            NS)
                _ok "Nameservers: $(echo "$result" | head -2 | tr '\n' ' ')"
                ;;
            TXT)
                # Detecta SPF/DMARC/DKIM — indica serviços de email
                echo "$result" | grep -qi "v=spf1\|dmarc\|domainkey" \
                    && _ok "SPF/DMARC/DKIM detectado"

                # Fingerprint de serviços via TXT (vazamento de stack)
                local svcs
                svcs=$(echo "$result" \
                    | grep -ioE 'google|microsoft|amazon|atlassian|salesforce|sendgrid|mailchimp|stripe|hubspot|zoom|dropbox' \
                    | sort -u | tr '\n' ' ' || true)
                [[ -n "$svcs" ]] && _find "Serviços detectados via TXT: ${svcs}"

                # Extrai ranges IP do SPF para later recon
                echo "$result" | grep 'v=spf1' \
                    | grep -oE 'ip[46]:[^ ]+' | sed 's/ip[46]://' \
                    >> "${BASE_DIR}/.spf_ips.tmp" 2>/dev/null || true
                ;;
        esac
        echo
    done

    # Salva IPs do SPF se houver
    if [[ -f "${BASE_DIR}/.spf_ips.tmp" ]] && [[ -s "${BASE_DIR}/.spf_ips.tmp" ]]; then
        sort -u "${BASE_DIR}/.spf_ips.tmp" >> "$out"
        _ok "IPs via SPF: $(wc -l < "${BASE_DIR}/.spf_ips.tmp" 2>/dev/null || echo 0)"
        rm -f "${BASE_DIR}/.spf_ips.tmp"
    fi

    # ── AXFR — Zone Transfer ───────────────────────────────────────────────────
    # Tenta obter toda a zona DNS via AXFR nos nameservers identificados.
    # Em ambientes mal configurados, expõe toda a infraestrutura interna.
    _tool_box "dig AXFR" "$TARGET" "Tentativa de Zone Transfer em cada NS" "dig AXFR TARGET @NS"

    local ns_list
    ns_list=$(dig +short "$TARGET" NS 2>/dev/null || true)

    if [[ -n "$ns_list" ]]; then
        while IFS= read -r ns; do
            [[ -z "$ns" ]] && continue
            ns="${ns%.}"  # Remove ponto final do FQDN

            local axfr
            # || true garante que pipefail não aborte em AXFR negado (exit != 0)
            axfr=$(timeout 10 dig AXFR "$TARGET" "@${ns}" 2>/dev/null \
                | grep -v '^;' | grep -v '^\s*$' || true)

            if [[ -n "$axfr" ]]; then
                _crit "ZONE TRANSFER POSSÍVEL via ${ns}!"
                echo "$axfr" | head -30 | sed 's/^/    /'
                echo "=== AXFR ${ns} ===" >> "$out"
                echo "$axfr" >> "$out"
            else
                _skip "AXFR bloqueado: ${ns}"
            fi
        done <<< "$ns_list"
    else
        _skip "Nenhum nameserver encontrado para AXFR."
    fi

    _log "PHASE 1 concluída"
    echo
    _ok "WHOIS + DNS concluído → whois_dns.txt"
}

# ==============================================================================
#  PHASE 2 — PASSIVE OSINT
#  Coleta passiva de emails, hosts e informações de infraestrutura.
#  Usa theHarvester com fontes abertas sem autenticação (sem risco de queima).
#  Usa crt.sh para Certificate Transparency — frequentemente revela subdomínios
#  internos que as demais ferramentas não encontram.
# ==============================================================================
phase_osint() {
    _phase "2" "PASSIVE RECON — OSINT"
    _confirm_phase "OSINT / theHarvester" || { _skip "Fase ignorada pelo operador."; return; }

    # ── theHarvester ───────────────────────────────────────────────────────────
    if _has_harvester; then
        # Fontes sem necessidade de API key e sem reverse-DNS excessivo
        local sources="baidu,certspotter,commoncrawl,crtsh,duckduckgo,gitlab,hackertarget"
        sources+=",hudsonrock,leaklookup,mojeek,otx,rapiddns,robtex,subdomaincenter"
        sources+=",subdomainfinderc99,thc,threatcrowd,urlscan,waybackarchive,windvane,yahoo"

        _tool_box "theHarvester" "$TARGET" \
            "Coleta passiva: emails, hosts, IPs" \
            "theHarvester -d ${TARGET} -l 100 -b [fontes]"

        # FIX: não usar 2>/dev/null no theHarvester.
        # Versões recentes escrevem output misto em stdout+stderr.
        # Redirecionamos stderr para um arquivo de log separado para diagnóstico.
        # Strippamos ANSI codes antes de qualquer grep para evitar que linhas
        # com escape sequences sejam descartadas incorretamente pelo grep -v.
        local h_stderr_log="${BASE_DIR}/.harvester_stderr.tmp"
        local h_raw_tmp="${BASE_DIR}/.harvester_raw.tmp"

        _run_harvester -d "$TARGET" -l 100 -b "$sources" \
            > "$h_raw_tmp" \
            2> "$h_stderr_log" \
        || true

        # Strip de ANSI codes para processamento limpo
        local h_out=""
        if [[ -s "$h_raw_tmp" ]]; then
            h_out=$(sed 's/\x1b\[[0-9;]*[mGKHF]//g' "$h_raw_tmp" \
                | grep -v "\.rev\.${TARGET}" \
                | grep -v '^[[:space:]]*$' || true)
        fi

        # Se stdout veio vazio, tenta capturar o que foi para stderr
        # (algumas versões do theHarvester misturam output em stderr)
        if [[ -z "$h_out" ]] && [[ -s "$h_stderr_log" ]]; then
            h_out=$(sed 's/\x1b\[[0-9;]*[mGKHF]//g' "$h_stderr_log" \
                | grep -v "\.rev\.${TARGET}" \
                | grep -v '^[[:space:]]*$' \
                | grep -viE '^\s*\[|\*\s+Searching|\*\s+Results:|Starting|Scanning|Error|Warning|Traceback|urllib' \
                || true)
        fi

        # Valida se h_out tem conteúdo operacional real:
        # 1 linha em branco ou só banner passa no -n mas não tem dados úteis
        local h_has_data=0
        if [[ -n "$h_out" ]]; then
            echo "$h_out" | grep -qE '@|\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|[a-zA-Z0-9]\.[a-zA-Z]{2,}' \
                && h_has_data=1 || true
        fi

        if [[ $h_has_data -eq 1 ]]; then
            # Extrai emails encontrados — filtra endereços de ruído conhecido
            local h_emails
            h_emails=$(echo "$h_out" \
                | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
                | grep -viE 'example|test|noreply|no-reply|@seclists|@cert\.br' \
                | sort -u || true)

            if [[ -n "$h_emails" ]]; then
                _find "Emails via theHarvester:"
                echo "$h_emails" | sed 's/^/    /'
                # Merge com emails já coletados no WHOIS
                { cat "${BASE_DIR}/emails.txt" 2>/dev/null; echo "$h_emails"; } \
                    | sort -u > "${BASE_DIR}/.emails_merge.tmp" \
                    && mv "${BASE_DIR}/.emails_merge.tmp" "${BASE_DIR}/emails.txt"
            fi

            local h_ips h_lines h_email_count
            # wc -l e grep -c ja retornam 0 sem match.
            # "|| echo 0" com pipefail ativo duplica: grep exit1 -> wc imprime 0 + || imprime 0 = "0\n0"
            h_lines=$(echo "$h_out" | wc -l | tr -d ' \t')
            h_ips=$( { echo "$h_out" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' 2>/dev/null || true; } | sort -u | wc -l | tr -d ' \t')
            h_email_count=$( { echo "$h_emails" | grep -c '@' 2>/dev/null; } | tr -d ' \t\n'; true)

            _tool_result "theHarvester" "${h_lines} linhas · ${h_ips} IPs · ${h_email_count} emails"
        else
            _skip "theHarvester: sem resultados operacionais nessa execução."
            # Mostra motivo quando stderr tem pistas (import error, API error, etc)
            if [[ -s "$h_stderr_log" ]]; then
                local err_hint
                err_hint=$(grep -iE 'error|exception|traceback|module|import|not found' \
                    "$h_stderr_log" 2>/dev/null | head -2 | sed 's/^/    /' || true)
                [[ -n "$err_hint" ]] && _warn "Diagnóstico theHarvester:\n${err_hint}"
            fi
        fi
        rm -f "$h_raw_tmp" "$h_stderr_log"
    else
        _skip "theHarvester / uv não encontrado. Instale: sudo apt install theHarvester"
    fi

    echo

    # ── crt.sh — Certificate Transparency ─────────────────────────────────────
    # CT logs registram todos os certificados emitidos — excelente fonte passiva
    # de subdomínios, inclusive subdomínios internos acessados por HTTPS
    _tool_box "crt.sh" "$TARGET" \
        "Certificate Transparency — subdomínios via CT logs" \
        "curl https://crt.sh/?q=%.${TARGET}&output=json"

    # FIX: removido o flag -f do curl.
    # -f faz o curl falhar silenciosamente em qualquer resposta não-2xx (503, 429, etc).
    # crt.sh pode retornar 503 em pico de carga — sem -f capturamos o HTTP code para diagnóstico.
    # Timeout aumentado para 45s: crt.sh é lento sob carga e 20s é insuficiente.
    local crt_tmp; crt_tmp=$(mktemp /tmp/bbr_crt_XXXX.json)
    local crt_http_code

    # curl -w '%{http_code}' ja imprime "000" quando falha (timeout, sem rede).
    # "|| echo 000" duplicaria: curl imprime 000 + || imprime 000 = "000000"
    crt_http_code=$(curl -s --max-time 45 \
        -o "$crt_tmp" \
        -w '%{http_code}' \
        "https://crt.sh/?q=%.${TARGET}&output=json" \
        2>/dev/null; true)
    crt_http_code=$(echo "$crt_http_code" | tr -d ' \n')

    local crt=""
    if [[ "$crt_http_code" == "200" ]] && [[ -s "$crt_tmp" ]]; then
        # jq preferido: mais robusto para entradas com \n (múltiplos nomes por cert)
        if command -v jq &>/dev/null; then
            crt=$(jq -r '.[].name_value' "$crt_tmp" 2>/dev/null \
                | tr ',' '\n' \
                | sed 's/\*\.//' \
                | grep -v '^$' \
                | sort -u || true)
        else
            # Fallback grep para quando jq não está disponível
            crt=$(grep -oP '"name_value":"\K[^"]+' "$crt_tmp" 2>/dev/null \
                | tr ',' '\n' \
                | sed 's/\*\.//' \
                | grep -v '^$' \
                | sort -u || true)
        fi
    fi

    rm -f "$crt_tmp"

    if [[ -n "$crt" ]]; then
        echo "$crt" > "${BASE_DIR}/crtsh.txt"
        _tool_result "crt.sh" "$(wc -l < "${BASE_DIR}/crtsh.txt") entradas (HTTP ${crt_http_code})"
        _ok "CT logs → subdomains_raw.txt receberá esses dados na Phase 3"
    else
        case "$crt_http_code" in
            000) _skip "crt.sh: timeout ou sem conectividade (${crt_http_code})" ;;
            429) _skip "crt.sh: rate limit atingido (429) — tente novamente em alguns minutos" ;;
            503) _skip "crt.sh: serviço indisponível (503) — sobrecarga no servidor" ;;
            *)   _skip "crt.sh: sem resultado (HTTP ${crt_http_code})" ;;
        esac
    fi

    # Contagem final de emails coletados
    COUNT_EMAILS=$([ -f "${BASE_DIR}/emails.txt" ] && wc -l < "${BASE_DIR}/emails.txt" || echo 0)
    COUNT_EMAILS=$(echo "$COUNT_EMAILS" | tr -d ' \t')
    [[ $COUNT_EMAILS -gt 0 ]] && _ok "${COUNT_EMAILS} emails únicos coletados → emails.txt"

    _log "PHASE 2 concluída"
    echo
    _ok "OSINT passivo concluído."
}

# ==============================================================================
#  PHASE 3 — SUBDOMAIN ENUMERATION + FILTRAGEM INTELIGENTE
#  Agrega resultados de múltiplas ferramentas e aplica pipeline de filtragem.
#
#  Pipeline:
#   1. Enumeration: subfinder + findomain + amass + crtsh → subdomains_raw.txt
#   2. DNS Resolution: dig A record em cada subdomínio → unique_ips.txt
#   3. HTTP Probe: httpx (ou curl fallback) → subdomains_alive.txt
#   4. Classification: detecta painéis, serviços críticos → subdomains_interesting.txt
#
#  Saídas geradas:
#   subdomains_raw.txt        → tudo que foi encontrado, deduplicado
#   unique_ips.txt            → IPs únicos resolvidos
#   subdomains_alive.txt      → apenas hosts com HTTP/S ativo
#   subdomains_interesting.txt → painéis admin, serviços sensíveis
# ==============================================================================
phase_subdomains() {
    _phase "3" "SUBDOMAIN ENUMERATION + FILTRAGEM"
    _confirm_phase "Subdomain Enumeration" || { _skip "Fase ignorada pelo operador."; return; }

    local raw="${BASE_DIR}/subdomains_raw.txt"
    local merge_tmp="${BASE_DIR}/.subs_merge.tmp"
    > "$merge_tmp"

    # ── Enumeração com múltiplas ferramentas ───────────────────────────────────
    local t_subs_start; t_subs_start=$(date +%s)

    if _has subfinder; then
        _tool_box "subfinder" "$TARGET" "Passive subdomain discovery" "subfinder -d ${TARGET} -silent"
        "$(_which subfinder)" -d "$TARGET" -silent 2>/dev/null >> "$merge_tmp" || true
        _tool_result "subfinder" "$(wc -l < "$merge_tmp") acumulado"
    else
        _skip "subfinder ausente."
    fi

    if _has findomain; then
        _tool_box "findomain" "$TARGET" "Passive subdomain discovery" "findomain -t ${TARGET} -q"
        "$(_which findomain)" -t "$TARGET" -q 2>/dev/null >> "$merge_tmp" || true
        _tool_result "findomain" "$(wc -l < "$merge_tmp") acumulado"
    else
        _skip "findomain ausente."
    fi

    if _has amass; then
        _tool_box "amass" "$TARGET" "Passive enumeration (pode demorar)" "amass enum -passive -d ${TARGET}"
        local amass_start; amass_start=$(date +%s)
        "$(_which amass)" enum -passive -d "$TARGET" 2>/dev/null >> "$merge_tmp" || true
        local amass_elapsed=$(( $(date +%s) - amass_start ))
        _tool_result "amass" "$(wc -l < "$merge_tmp") acumulado · ${amass_elapsed}s"
    else
        _skip "amass ausente."
    fi

    # Inclui resultados do crt.sh coletados na fase anterior
    [[ -f "${BASE_DIR}/crtsh.txt" ]] && cat "${BASE_DIR}/crtsh.txt" >> "$merge_tmp"

    # Deduplicação, filtragem do domínio alvo e remoção de wildcards
    sort -u "$merge_tmp" \
        | grep -E "(^|\.)${TARGET//./\\.}$" \
        | grep -v '^\*' \
        > "$raw" 2>/dev/null || true
    rm -f "$merge_tmp"

    COUNT_SUBDOMAINS=$(wc -l < "$raw" 2>/dev/null || echo 0)
    local t_subs_elapsed=$(( $(date +%s) - t_subs_start ))
    echo
    _ok "Total único: ${BOLD}${COUNT_SUBDOMAINS}${RESET} subdomínios → subdomains_raw.txt (${t_subs_elapsed}s)"

    [[ "$COUNT_SUBDOMAINS" -eq 0 ]] && {
        _warn "Nenhum subdomínio encontrado. Verifique conectividade e ferramentas."
        return
    }

    # ── Resolução de IPs ───────────────────────────────────────────────────────
    echo
    _info "Resolvendo IPs de ${COUNT_SUBDOMAINS} subdomínios..."
    echo
    printf "  ${BOLD}%-48s  %s${RESET}\n" "SUBDOMÍNIO" "IP"
    printf "  %s\n" "$(printf '─%.0s' {1..62})"

    UNIQUE_IPS=()
    local resolved_tmp="${BASE_DIR}/.resolved.tmp"
    > "$resolved_tmp"

    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        local ip
        ip=$(dig +short "$sub" A 2>/dev/null | grep -E '^[0-9]+\.' | head -1 || true)
        if [[ -n "$ip" ]]; then
            printf "  ${G}%-48s  ${C}%s${RESET}\n" "$sub" "$ip"
            echo "${sub} ${ip}" >> "$resolved_tmp"
            UNIQUE_IPS+=("$ip")
        else
            printf "  ${DIM}%-48s  N/A${RESET}\n" "$sub"
        fi
    done < "$raw"

    # Salva IPs únicos — usado pelo nmap nas fases seguintes
    printf '%s\n' "${UNIQUE_IPS[@]}" | sort -uV > "${BASE_DIR}/unique_ips.txt"
    COUNT_IPS=$(wc -l < "${BASE_DIR}/unique_ips.txt" 2>/dev/null || echo 0)
    echo
    _ok "IPs únicos resolvidos: ${BOLD}${COUNT_IPS}${RESET} → unique_ips.txt"

    # ── HTTP Probe — filtra hosts vivos ────────────────────────────────────────
    # Aqui aplicamos a filtragem inteligente principal:
    # só os hosts com HTTP/S ativo serão passados para gobuster, nuclei, etc.
    echo
    _info "Filtrando hosts vivos via HTTP/S..."

    local alive_out="${BASE_DIR}/subdomains_alive.txt"
    > "$alive_out"
    ALIVE_HOSTS=()

    if _has httpx; then
        _tool_box "httpx" "$TARGET" \
            "HTTP probe com fingerprint completo" \
            "httpx -l subdomains_raw.txt -silent -sc -title -td -threads 50"

        "$(_which httpx)" -l "$raw" -silent \
            -status-code -title -tech-detect \
            -follow-redirects -threads 50 -timeout 10 \
            -o "$alive_out" 2>/dev/null || true

        # Testa também portas alternativas comuns em ambientes corporativos
        "$(_which httpx)" -l "$raw" -silent \
            -ports 8080,8443,8888,9090,4443,3000,5000 \
            -status-code -title -threads 30 -timeout 8 \
            2>/dev/null >> "$alive_out" || true

        sort -u "$alive_out" -o "$alive_out" 2>/dev/null || true
    else
        # Fallback curl — mais lento mas sempre disponível
        _skip "httpx ausente. Fallback: curl simples..."
        while IFS= read -r sub; do
            [[ -z "$sub" ]] && continue
            local code
            code=$(curl -sk -o /dev/null -w '%{http_code}' \
                --max-time 6 "https://${sub}" 2>/dev/null || echo "000")
            [[ "$code" =~ ^[2345] ]] && echo "https://${sub} [${code}]" >> "$alive_out"
        done < "$raw"
    fi

    COUNT_ALIVE=$(wc -l < "$alive_out" 2>/dev/null || echo 0)
    _tool_result "HTTP probe" "${COUNT_ALIVE} hosts vivos"

    # Popula array global ALIVE_HOSTS (usado em todas as fases seguintes)
    while IFS= read -r line; do
        local url
        url=$(echo "$line" | grep -oE 'https?://[^ ]+' | head -1 || true)
        [[ -n "$url" ]] && ALIVE_HOSTS+=("$url")
    done < "$alive_out"

    # ── Exibe hosts vivos com cor por status code ──────────────────────────────
    echo
    printf "  ${BOLD}%-60s  %s${RESET}\n" "HOST" "STATUS"
    printf "  %s\n" "$(printf '─%.0s' {1..70})"
    while IFS= read -r line; do
        local code
        code=$(echo "$line" | grep -oP '\[\K[0-9]+(?=\])' | head -1 || true)
        case "${code:0:1}" in
            2) printf "  ${G}%s${RESET}\n" "$line" ;;
            3) printf "  ${C}%s${RESET}\n" "$line" ;;
            4) printf "  ${Y}%s${RESET}\n" "$line" ;;
            5) printf "  ${R}%s${RESET}\n" "$line" ;;
            *) printf "  %s\n" "$line" ;;
        esac
    done < "$alive_out"
    echo

    # ── Classificação de hosts interessantes ───────────────────────────────────
    # Identifica painéis administrativos e serviços críticos pelo título/URL.
    # Esses hosts recebem prioridade em fases de exploração.
    local panel_kw="admin|panel|dashboard|manage|login|portal|console|phpmyadmin|cpanel"
    panel_kw+="|webmin|jenkins|gitlab|grafana|kibana|elastic|sonar|jira|confluence"
    panel_kw+="|nagios|zabbix|prometheus|pgadmin|adminer|portainer|rancher|k8s|kubernetes"

    local interesting="${BASE_DIR}/subdomains_interesting.txt"
    grep -iE "$panel_kw" "$alive_out" 2>/dev/null > "$interesting" || true

    if [[ -s "$interesting" ]]; then
        _find "PAINÉIS E SERVIÇOS CRÍTICOS DETECTADOS:"
        while IFS= read -r line; do
            printf "    ${BOLD}${Y}►${RESET} %s\n" "$line"
            PANELS_FOUND+=("$line")
        done < "$interesting"
        echo
    else
        _skip "Nenhum painel admin detectado pela URL/título."
    fi

    rm -f "$resolved_tmp"
    _log "PHASE 3 concluída — ${COUNT_SUBDOMAINS} subs, ${COUNT_ALIVE} alive, ${COUNT_IPS} IPs"
    _ok "Filtragem concluída → subdomains_raw/alive/interesting/unique_ips"
}

# ==============================================================================
#  PHASE 4 — WAF DETECTION
#  Detecta Web Application Firewalls em todos os hosts vivos.
#  Resultado é crítico para as fases seguintes: hosts sem WAF permitem
#  scans mais agressivos; hosts com WAF exigem técnicas de evasão.
# ==============================================================================
phase_waf() {
    _phase "4" "WAF DETECTION"
    _confirm_phase "WAF Detection" || { _skip "Fase ignorada pelo operador."; return; }

    if ! _has wafw00f; then
        _skip "wafw00f ausente. Instale: pip install wafw00f --break-system-packages"
        return
    fi

    [[ ${#ALIVE_HOSTS[@]} -eq 0 ]] && { _warn "Nenhum host vivo. Execute fase 3 antes."; return; }

    local waf_out="${BASE_DIR}/waf.txt"
    > "$waf_out"
    local count=0 total=${#ALIVE_HOSTS[@]}

    _tool_box "wafw00f" "$TARGET" \
        "Fingerprint de WAF em hosts vivos" \
        "wafw00f <host>"

    for host in "${ALIVE_HOSTS[@]}"; do
        local domain
        domain=$(echo "$host" | grep -oP '(?<=://)([^/:]+)' || true)
        [[ -z "$domain" ]] && continue

        ((count++))
        printf "  ${DIM}[%d/%d]${RESET} %-45s " "$count" "$total" "$domain"

        local result
        result=$(timeout 15 "$(_which wafw00f)" "$host" 2>/dev/null | tail -8 || true)
        { echo "=== ${host} ==="; echo "$result"; echo; } >> "$waf_out"

        if echo "$result" | grep -qi "is behind"; then
            local waf_name
            waf_name=$(echo "$result" | grep -oi 'behind [A-Za-z0-9 ().\-]*' | head -1 | sed 's/behind //' || echo "WAF")
            printf "${Y}WAF: %s${RESET}\n" "$waf_name"
            WAFS_FOUND+=("${domain}: ${waf_name}")
        elif echo "$result" | grep -qi "No WAF\|not detected"; then
            printf "${G}sem WAF${RESET} ${DIM}(scan agressivo permitido)${RESET}\n"
        else
            printf "${DIM}indeterminado${RESET}\n"
        fi

        [[ $count -ge 20 ]] && { echo; _warn "Limitando WAF a 20 hosts."; break; }
    done

    echo
    [[ ${#WAFS_FOUND[@]} -gt 0 ]] && \
        _warn "${#WAFS_FOUND[@]} host(s) com WAF detectado → waf.txt"
    [[ ${#WAFS_FOUND[@]} -eq 0 ]] && \
        _ok "Nenhum WAF detectado. Ambiente potencialmente sem proteção web."

    _log "PHASE 4 concluída"
    _ok "WAF detection concluído → waf.txt"
}

# ==============================================================================
#  PHASE 5 — FINGERPRINTING (WhatWeb + Headers)
#  Identifica tecnologias, versões e configurações de segurança HTTP.
#  Headers ausentes como HSTS e CSP são findings reportáveis.
#  X-Powered-By e Server com versão exposta são alvos de exploração.
# ==============================================================================
phase_fingerprint() {
    _phase "5" "FINGERPRINTING — WhatWeb + HTTP Headers"
    _confirm_phase "Fingerprinting" || { _skip "Fase ignorada pelo operador."; return; }

    [[ ${#ALIVE_HOSTS[@]} -eq 0 ]] && { _warn "Nenhum host vivo. Execute fase 3 antes."; return; }

    local fp_out="${BASE_DIR}/fingerprint.txt"
    > "$fp_out"

    # ── WhatWeb ────────────────────────────────────────────────────────────────
    if _has whatweb; then
        _tool_box "whatweb" "$TARGET" \
            "Fingerprint de CMS, frameworks e versões" \
            "whatweb --aggression 3 <hosts>"

        local ww_targets=()
        local lim=0
        for h in "${ALIVE_HOSTS[@]}"; do
            ww_targets+=("$h"); ((lim++)); [[ $lim -ge 30 ]] && break
        done

        "$(_which whatweb)" --color=always --aggression=3 \
            "${ww_targets[@]}" 2>/dev/null | tee "$fp_out" || true

        # Tecnologias com maior frequência — útil para priorizar CVEs
        echo
        _info "Tecnologias mais frequentes:"
        grep -oE 'WordPress[^,)]*|Joomla[^,)]*|Drupal[^,)]*|Laravel[^,)]*|Django[^,)]*|PHP[^,)]*|Apache[^,)]*|Nginx[^,)]*|IIS[^,)]*|Tomcat[^,)]*' \
            "$fp_out" 2>/dev/null \
            | sort | uniq -c | sort -rn | head -10 \
            | while read -r cnt tech; do
                printf "  ${C}%3dx${RESET}  %s\n" "$cnt" "$tech"
            done || true
    else
        _skip "whatweb ausente."
    fi

    # ── HTTP Security Headers ──────────────────────────────────────────────────
    # Headers ausentes são findings de nível informacional a médio em pentests.
    echo
    _info "Auditando security headers nos hosts vivos..."
    echo

    local sec_hdrs=(
        "Strict-Transport-Security"
        "X-Frame-Options"
        "X-Content-Type-Options"
        "Content-Security-Policy"
        "X-XSS-Protection"
        "Referrer-Policy"
    )
    local lim=0

    printf "  ${BOLD}%-50s  %s${RESET}\n" "HOST" "OBSERVAÇÃO"
    printf "  %s\n" "$(printf '─%.0s' {1..70})"

    for host in "${ALIVE_HOSTS[@]}"; do
        local hdrs
        hdrs=$(curl -sk -I --max-time 8 "$host" 2>/dev/null || true)
        [[ -z "$hdrs" ]] && continue

        # Server + X-Powered-By revelam stack técnico — útil para CVE hunting
        local srv xpb
        srv=$(echo "$hdrs" | grep -i '^server:'     | head -1 | sed 's/[Ss]erver: *//' | tr -d '\r' || true)
        xpb=$(echo "$hdrs" | grep -i '^x-powered-by:' | head -1 | sed 's/[Xx]-[Pp]owered-[Bb]y: *//' | tr -d '\r' || true)

        [[ -n "$xpb" ]] && _find "X-Powered-By: ${xpb} → ${host}"

        local miss=""
        for hdr in "${sec_hdrs[@]}"; do
            echo "$hdrs" | grep -qi "^${hdr}:" || miss+="$(echo "${hdr}" | sed 's/Strict-Transport-Security/HSTS/; s/Content-Security-Policy/CSP/') "
        done

        printf "  %-50s" "${host:8:48}"
        [[ -n "$srv" ]] && printf "  ${DIM}%s${RESET}" "$srv"
        [[ -n "$miss" ]] && printf "  ${Y}[missing: %s]${RESET}" "${miss// /, }"
        echo

        { echo "=== ${host} ==="; echo "$hdrs"; echo "Missing: ${miss}"; echo; } \
            >> "${BASE_DIR}/headers.txt" 2>/dev/null || true

        ((lim++)); [[ $lim -ge 30 ]] && break
    done

    _log "PHASE 5 concluída"
    echo
    _ok "Fingerprinting concluído → fingerprint.txt / headers.txt"
}

# ==============================================================================
#  PHASE 6 — PORT SCANNING (nmap)
#  Varre portas nos IPs únicos resolvidos na fase de subdomínios.
#  Fase 6a: top 1000 portas com detecção de versão (visão geral)
#  Fase 6b: portas críticas específicas com scripts de auth/default
#  Apresenta resultados no formato: IP + HOST + PORTA + SERVIÇO
# ==============================================================================
phase_nmap() {
    _phase "6" "PORT SCANNING — nmap"
    _confirm_phase "nmap Port Scan" || { _skip "Fase ignorada pelo operador."; return; }

    if ! _has nmap; then _skip "nmap ausente. Instale: sudo apt install nmap"; return; fi

    local ip_file="${BASE_DIR}/unique_ips.txt"
    [[ ! -f "$ip_file" ]] || [[ ! -s "$ip_file" ]] && {
        _warn "unique_ips.txt não encontrado ou vazio. Execute fase 3 antes."
        return
    }

    local ip_c; ip_c=$(wc -l < "$ip_file")
    _info "Alvos: ${ip_c} IPs únicos"

    # ── Fase 6a: scan geral (top 1000) ────────────────────────────────────────
    _tool_box "nmap" "$TARGET" \
        "Top 1000 portas + versão + banner" \
        "nmap -iL unique_ips.txt --open -T4 -sV"

    nmap -iL "$ip_file" \
        --open -T4 -sV --version-intensity 5 \
        --script="banner,http-title,ssl-cert" \
        -oN "${BASE_DIR}/nmap.txt" \
        2>/dev/null || true

    # ── Fase 6b: portas críticas com scripts de autenticação ──────────────────
    local CRIT_PORTS="21,22,23,25,53,3306,3389,4444,5432,5900,5985,5986,6379,9200,11211,27017"

    _tool_box "nmap" "$TARGET" \
        "Portas críticas com scripts auth/default" \
        "nmap -p ${CRIT_PORTS} --script auth,default"

    nmap -iL "$ip_file" \
        --open -T4 \
        -p "$CRIT_PORTS" -sV --version-intensity 7 \
        --script="auth,default" \
        -oN "${BASE_DIR}/nmap_critical.txt" \
        2>/dev/null || true

    # ── Apresentação dos resultados: IP + HOST + PORTA + SERVIÇO ──────────────
    echo
    _info "Resultado do scan:"
    echo

    # Parseia os dois arquivos nmap e monta saída estruturada
    local current_ip="" current_host=""
    while IFS= read -r line; do
        # Detecta qual IP está sendo reportado
        if echo "$line" | grep -qE '^Nmap scan report for'; then
            current_host=$(echo "$line" | grep -oP '(?<=for ).*' || true)
            current_ip=$(echo "$current_host" | grep -oP '\(.*\)' | tr -d '()' || true)
            [[ -z "$current_ip" ]] && current_ip="$current_host" && current_host=""
        fi

        # Detecta linha de porta aberta
        if echo "$line" | grep -qE '^[0-9]+/(tcp|udp).*open'; then
            local port svc info
            port=$(echo "$line" | awk '{print $1}')
            svc=$(echo  "$line" | awk '{print $3}')
            info=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | sed 's/^ *//')

            # Portas críticas — destacar com bloco visual
            local is_crit=0
            for cp in 21 23 3389 5900 6379 9200 11211 27017 4444 5432 3306; do
                echo "$port" | grep -q "^${cp}/" && is_crit=1 && break
            done

            if [[ $is_crit -eq 1 ]]; then
                echo
                printf "  ${BOLD}${BG_R}  ◉ CRITICAL PORT  ${RESET}\n"
                printf "  ${BOLD}${R}  HOST${RESET} : %-40s\n" "${current_host:-${current_ip}}"
                printf "  ${BOLD}${R}  IP  ${RESET} : %-40s\n" "$current_ip"
                printf "  ${BOLD}${R}  PORT${RESET} : %-40s\n" "$port"
                printf "  ${BOLD}${R}  INFO${RESET} : %-40s\n" "${svc} ${info}"
                echo
                CRIT_PORTS_FOUND+=("${current_ip} ${port} ${svc}")
            else
                printf "  ${G}%-18s${RESET}  ${W}%-8s${RESET}  ${C}%-18s${RESET}  ${DIM}%s${RESET}\n" \
                    "${current_ip}" "$port" "$svc" "${info:0:30}"
            fi
        fi
    done < <(cat "${BASE_DIR}/nmap.txt" "${BASE_DIR}/nmap_critical.txt" 2>/dev/null | sort -u || true)

    echo
    _log "PHASE 6 concluída"
    _ok "Port scan concluído → nmap.txt / nmap_critical.txt"
}

# ==============================================================================
#  PHASE 7 — SSL/TLS ANALYSIS
#  Analisa configuração TLS dos hosts HTTPS.
#  Distingue claramente:
#    INFORMATIVO → configuração normal esperada
#    ATENÇÃO     → protocolo deprecado (TLS 1.1)
#    CRÍTICO     → protocolos inseguros (SSLv3, TLS 1.0, RC4, NULL, EXPORT)
#  NÃO trata ausência de TLS 1.0/1.1 como problema — isso é o comportamento correto.
# ==============================================================================
phase_ssl() {
    _phase "7" "SSL/TLS ANALYSIS"
    _confirm_phase "SSL/TLS" || { _skip "Fase ignorada pelo operador."; return; }

    local ssl_out="${BASE_DIR}/ssl.txt"
    > "$ssl_out"
    local count=0

    # Filtra apenas hosts HTTPS — HTTP puro não tem TLS para analisar
    local https_hosts=()
    for h in "${ALIVE_HOSTS[@]}"; do
        echo "$h" | grep -q "^https" && https_hosts+=("$h")
    done

    [[ ${#https_hosts[@]} -eq 0 ]] && { _skip "Nenhum host HTTPS para analisar."; return; }
    _info "${#https_hosts[@]} hosts HTTPS para análise TLS"

    for host in "${https_hosts[@]}"; do
        local domain
        domain=$(echo "$host" | grep -oP '(?<=://)([^/:]+)' || true)
        [[ -z "$domain" ]] && continue

        printf "\n  ${BOLD}${C}┌─ TLS: %s ${RESET}\n" "$domain"

        if _has sslscan; then
            local scan
            scan=$(timeout 30 "$(_which sslscan)" --no-colour "$domain" 2>/dev/null || true)
            echo "$scan" >> "$ssl_out"

            # ── CRÍTICO: protocolos realmente inseguros ────────────────────────
            local crit_proto
            crit_proto=$(echo "$scan" \
                | grep -iE "SSLv[23]|TLSv1\.0" \
                | grep -i "enabled\|accepted" || true)
            if [[ -n "$crit_proto" ]]; then
                printf "  ${BOLD}${R}  │ ◉ CRÍTICO${RESET} — Protocolo inseguro habilitado:\n"
                echo "$crit_proto" | sed 's/^/  │   /'
            fi

            # ── ATENÇÃO: TLS 1.1 deprecado mas não imediatamente exploitável ──
            local warn_proto
            warn_proto=$(echo "$scan" \
                | grep -iE "TLSv1\.1" \
                | grep -i "enabled\|accepted" || true)
            [[ -n "$warn_proto" ]] && \
                printf "  ${Y}  │ ▲ ATENÇÃO${RESET} — TLS 1.1 deprecado (RFC 8996)\n"

            # ── CRÍTICO: cipher suites inseguras ──────────────────────────────
            local weak_ciphers
            weak_ciphers=$(echo "$scan" \
                | grep -iE "RC4|DES(?!\s*-CBC3)|NULL|EXPORT|anon" || true)
            [[ -n "$weak_ciphers" ]] && \
                printf "  ${BOLD}${R}  │ ◉ CRÍTICO${RESET} — Cipher inseguro: %s\n" \
                    "$(echo "$weak_ciphers" | head -1 | xargs)"

            # ── ATENÇÃO: certificado próximo do vencimento ─────────────────────
            local exp
            exp=$(echo "$scan" | grep -i "Not valid after" | grep -oP '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1 || true)
            if [[ -n "$exp" ]]; then
                local exp_e now_e days
                exp_e=$(date -d "$exp" +%s 2>/dev/null || echo 9999999999)
                now_e=$(date +%s)
                days=$(( (exp_e - now_e) / 86400 ))
                if [[ $days -lt 0 ]]; then
                    printf "  ${BOLD}${R}  │ ◉ CRÍTICO${RESET} — Certificado EXPIRADO há %d dias\n" $(( -days ))
                elif [[ $days -lt 30 ]]; then
                    printf "  ${Y}  │ ▲ ATENÇÃO${RESET} — Certificado expira em %d dias (%s)\n" "$days" "$exp"
                else
                    printf "  ${DIM}  │ ℹ  Certificado válido por %d dias${RESET}\n" "$days"
                fi
            fi

            # ── INFORMATIVO: TLS 1.2/1.3 habilitados (comportamento normal) ───
            echo "$scan" | grep -qiE "TLSv1\.2.*enabled|TLSv1\.3.*enabled" \
                && printf "  ${DIM}  │ ℹ  TLS 1.2/1.3 habilitado (OK)${RESET}\n"

        else
            # Fallback openssl quando sslscan não está disponível
            local cert
            cert=$(echo | timeout 5 openssl s_client \
                -connect "${domain}:443" -servername "$domain" 2>/dev/null \
                | openssl x509 -noout -subject -dates -issuer 2>/dev/null || true)
            if [[ -n "$cert" ]]; then
                echo "$cert" >> "$ssl_out"
                local exp_raw
                exp_raw=$(echo "$cert" | grep 'notAfter' | grep -oP '(?<=notAfter=).+' || true)
                if [[ -n "$exp_raw" ]]; then
                    local exp_e now_e days
                    exp_e=$(date -d "$exp_raw" +%s 2>/dev/null || echo 9999999999)
                    now_e=$(date +%s); days=$(( (exp_e - now_e) / 86400 ))
                    [[ $days -lt 30 ]] && printf "  ${Y}  │ ▲ ATENÇÃO${RESET} — Cert expira em %d dias\n" "$days" \
                                       || printf "  ${DIM}  │ ℹ  Cert válido por %d dias${RESET}\n" "$days"
                fi
            else
                printf "  ${DIM}  │ ℹ  Não foi possível obter certificado${RESET}\n"
            fi
        fi

        printf "  ${BOLD}${C}  └───────────────────${RESET}\n"

        ((count++))
        [[ $count -ge 15 ]] && { echo; _warn "Limitando a 15 hosts."; break; }
    done

    echo
    _log "PHASE 7 concluída"
    _ok "SSL/TLS concluído → ssl.txt"
}

# ==============================================================================
#  PHASE 8 — DIRECTORY ENUMERATION
#  Brute force de diretórios/arquivos apenas em hosts validados como vivos.
#  Usa feroxbuster (preferido: recursivo) → gobuster → ffuf como fallback.
#  Filtra wildcard responses antes do brute force para evitar falsos positivos.
#  Mostra progresso claro por host e resultado inline no terminal.
# ==============================================================================
phase_gobuster() {
    _phase "8" "DIRECTORY ENUMERATION"
    _confirm_phase "Directory Enumeration" || { _skip "Fase ignorada pelo operador."; return; }

    if ! _has gobuster && ! _has feroxbuster && ! _has ffuf; then
        _skip "Nenhuma ferramenta de directory brute force encontrada."
        _info "Instale: sudo apt install gobuster feroxbuster ffuf"
        return
    fi

    if [[ -z "${WL_DIRS:-}" ]] || [[ ! -f "$WL_DIRS" ]]; then
        printf "  ${C}[?]${RESET} Caminho da wordlist: "
        read -r WL_DIRS || true
        [[ ! -f "${WL_DIRS:-}" ]] && { _err "Wordlist não encontrada."; return; }
    fi

    [[ ${#ALIVE_HOSTS[@]} -eq 0 ]] && { _warn "Nenhum host vivo. Execute fase 3 antes."; return; }

    local entries; entries=$(wc -l < "$WL_DIRS")
    _info "Wordlist: ${WL_DIRS} (${entries} entradas)"

    # Extensões que indicam arquivos sensíveis ou vetores de ataque
    local ext="php,asp,aspx,jsp,html,txt,bak,sql,gz,zip,conf,env,log,yaml,json,xml,key,pem"

    local gob_out="${BASE_DIR}/gobuster.txt"
    > "$gob_out"

    local total="${#ALIVE_HOSTS[@]}" current=0

    for host in "${ALIVE_HOSTS[@]}"; do
        ((current++))
        local domain
        domain=$(echo "$host" | grep -oP '(?<=://)([^/:]+)' || true)
        [[ -z "$domain" ]] && continue

        # ── Validação pré-brute-force ──────────────────────────────────────────
        # Detecta wildcard: hosts que retornam 200 para qualquer path aleatório
        # tornam o brute force inútil (tudo aparece como "encontrado")
        local rand_path="/blackbox_recon_$(head /dev/urandom | tr -dc 'a-z0-9' | head -c 12 2>/dev/null || echo 'xtest123abc')"
        local wildcard_code
        wildcard_code=$(curl -sk -o /dev/null -w '%{http_code}' \
            --max-time 5 "${host}${rand_path}" 2>/dev/null || echo "000")

        printf "\n  ${BOLD}[%d/%d]${RESET} ${C}%s${RESET}\n" "$current" "$total" "$host"

        if [[ "$wildcard_code" == "200" ]]; then
            printf "      ${Y}→ wildcard detectado (200 para path aleatório) — brute force ignorado${RESET}\n"
            echo "=== ${host} ===" >> "$gob_out"
            echo "SKIP: wildcard response (200 para paths aleatórios)" >> "$gob_out"
            echo >> "$gob_out"
            continue
        fi

        # ── Executa a ferramenta disponível ───────────────────────────────────
        local raw=""
        if _has feroxbuster; then
            raw=$(timeout 180 "$(_which feroxbuster)" \
                --url "$host" --wordlist "$WL_DIRS" \
                --extensions "$ext" --status-codes "$PENTEST_CODES" \
                --threads 30 --timeout 10 --depth 2 \
                --quiet --no-recursion 2>/dev/null | grep -v '^#' || true)

        elif _has gobuster; then
            raw=$(timeout 180 "$(_which gobuster)" dir \
                -u "$host" -w "$WL_DIRS" \
                -s "$PENTEST_CODES" -b "" \
                -x "$ext" -k -t 30 --no-error -q \
                2>/dev/null || true)

        elif _has ffuf; then
            raw=$(timeout 180 "$(_which ffuf)" \
                -u "${host}/FUZZ" -w "$WL_DIRS" \
                -mc "200,204,301,302,307,308,401,403,405,500,503" \
                -t 30 -timeout 10 -s 2>/dev/null || true)
        fi

        # ── Exibe resultado com cor e destaque ────────────────────────────────
        if [[ -z "$raw" ]]; then
            printf "      ${DIM}→ sem resultados úteis${RESET}\n"
            echo "=== ${host} ===" >> "$gob_out"
            echo "sem resultados" >> "$gob_out"
            echo >> "$gob_out"
        else
            local path_count
            path_count=$(echo "$raw" | grep -c '[0-9]' 2>/dev/null || echo 0)
            printf "      ${G}→ %d path(s) relevante(s)${RESET}\n" "$path_count"

            echo "=== ${host} ===" >> "$gob_out"
            echo "$raw" | while IFS= read -r entry; do
                [[ -z "$entry" ]] && continue
                local st
                st=$(echo "$entry" | grep -oP '\(Status: \K[0-9]+|\[([0-9]+)\]' \
                    | grep -oP '[0-9]+' | head -1 || true)
                case "${st:0:1}" in
                    2) printf "        ${G}%s${RESET}\n" "$entry" ;;
                    3) printf "        ${C}%s${RESET}\n" "$entry" ;;
                    4) printf "        ${Y}%s${RESET}\n" "$entry" ;;
                    5) printf "        ${R}%s${RESET}\n" "$entry" ;;
                    *) printf "        %s\n" "$entry" ;;
                esac
                echo "  $entry" >> "$gob_out"
            done
            echo >> "$gob_out"

            # Destaca arquivos sensíveis que nunca deveriam estar expostos
            echo "$raw" \
                | grep -iE '\.(bak|sql|env|config|git|tar\.gz|\.zip|log|pem|key|p12|pfx)(\s|\[|$)' \
                2>/dev/null \
                | while IFS= read -r e; do _crit "ARQUIVO SENSÍVEL EXPOSTO: ${e}"; done || true
        fi

        # Limite operacional: máximo 15 hosts para não tornar a operação excessivamente longa
        [[ $current -ge 15 ]] && { echo; _warn "Limitando a 15 hosts."; break; }
    done

    echo
    _log "PHASE 8 concluída"
    _ok "Directory enumeration concluído → gobuster.txt"
}

# ==============================================================================
#  PHASE 9 — URL COLLECTION
#  Coleta histórico de URLs via Wayback Machine, Common Crawl e crawl ativo.
#  Classifica URLs por categoria de risco (API, params, endpoints sensíveis).
#  Output: urls_final.txt — usado nas fases 10 (JS) e 12 (Takeover)
# ==============================================================================
phase_urls() {
    _phase "9" "URL COLLECTION"
    _confirm_phase "URL Collection" || { _skip "Fase ignorada pelo operador."; return; }

    local merge="${BASE_DIR}/.urls_merge.tmp"
    > "$merge"
    local tools_used=0

    if _has gau; then
        _tool_box "gau" "$TARGET" \
            "URLs históricas via Wayback + Common Crawl" \
            "gau --subs ${TARGET}"
        "$(_which gau)" --subs "$TARGET" 2>/dev/null >> "$merge" || true
        _tool_result "gau" "$(wc -l < "$merge" 2>/dev/null || echo 0) URLs"
        ((tools_used++))
    else
        _skip "gau ausente."
    fi

    if _has waybackurls; then
        _tool_box "waybackurls" "$TARGET" \
            "URLs do Wayback Machine" \
            "echo ${TARGET} | waybackurls"
        echo "$TARGET" | "$(_which waybackurls)" 2>/dev/null >> "$merge" || true
        _tool_result "waybackurls" "$(wc -l < "$merge" 2>/dev/null || echo 0) URLs acumulado"
        ((tools_used++))
    else
        _skip "waybackurls ausente."
    fi

    if _has katana && [[ ${#ALIVE_HOSTS[@]} -gt 0 ]]; then
        _tool_box "katana" "$TARGET" \
            "Crawl ativo com análise de JS" \
            "katana -silent -depth 3 -js-crawl"
        printf '%s\n' "${ALIVE_HOSTS[@]}" | head -10 \
            | "$(_which katana)" -silent -depth 3 -js-crawl \
            2>/dev/null >> "$merge" || true
        _tool_result "katana" "$(wc -l < "$merge" 2>/dev/null || echo 0) URLs acumulado"
        ((tools_used++))
    else
        _skip "katana ausente ou sem hosts vivos."
    fi

    if _has hakrawler && [[ ${#ALIVE_HOSTS[@]} -gt 0 ]]; then
        _tool_box "hakrawler" "$TARGET" \
            "Crawl complementar" \
            "hakrawler -d 2"
        printf '%s\n' "${ALIVE_HOSTS[@]}" | head -10 \
            | "$(_which hakrawler)" -d 2 2>/dev/null >> "$merge" || true
        _tool_result "hakrawler" "$(wc -l < "$merge" 2>/dev/null || echo 0) URLs acumulado"
        ((tools_used++))
    fi

    if [[ $tools_used -eq 0 ]]; then
        _warn "Nenhuma ferramenta de URL collection disponível."
        _info "Instale: go install github.com/lc/gau/v2/cmd/gau@latest"
        rm -f "$merge"
        return
    fi

    local urls_out="${BASE_DIR}/urls_final.txt"
    sort -u "$merge" > "$urls_out" 2>/dev/null || true
    rm -f "$merge"

    COUNT_URLS=$(wc -l < "$urls_out" 2>/dev/null || echo 0)
    _ok "URLs únicas: ${BOLD}${COUNT_URLS}${RESET} → urls_final.txt"

    # ── Classificação de URLs por categoria ────────────────────────────────────
    echo
    local api_c params_c sens_c
    api_c=$(grep -ciE '/api/|/v[0-9]+/|/rest/|/graphql|/rpc|/endpoint' "$urls_out" 2>/dev/null || echo 0)
    params_c=$(grep -cE '(\?|&)[a-zA-Z0-9_]+=.+' "$urls_out" 2>/dev/null || echo 0)
    sens_c=$(grep -ciE 'admin|manage|panel|login|auth|token|secret|password|config|backup|debug|\.env|\.git' "$urls_out" 2>/dev/null || echo 0)

    printf "  ${C}%-26s${RESET}  ${W}%s${RESET}\n" "API endpoints detectados:"   "$api_c"
    printf "  ${C}%-26s${RESET}  ${W}%s${RESET}\n" "URLs com parâmetros:"        "$params_c"
    printf "  ${C}%-26s${RESET}  ${W}%s${RESET}\n" "URLs potenc. sensíveis:"     "$sens_c"

    [[ "$sens_c" -gt 0 ]] && \
        _find "${sens_c} URLs potencialmente sensíveis detectadas"

    _log "PHASE 9 concluída — ${COUNT_URLS} URLs"
    _ok "URL collection concluído → urls_final.txt"
}

# ==============================================================================
#  PHASE 10 — JS ANALYSIS + SECRET EXTRACTION
#  Baixa arquivos JavaScript e extrai padrões de secrets (API keys, tokens,
#  credenciais hardcoded). Também extrai endpoints internos referenciados no JS.
#  Patterns cobertos: AWS, Stripe, GitHub, Slack, SendGrid, JWT, tokens genéricos
# ==============================================================================
phase_js() {
    _phase "10" "JS ANALYSIS + SECRET EXTRACTION"
    _confirm_phase "JS Analysis" || { _skip "Fase ignorada pelo operador."; return; }

    local urls_file="${BASE_DIR}/urls_final.txt"
    if [[ ! -f "$urls_file" ]] || [[ ! -s "$urls_file" ]]; then
        _warn "urls_final.txt não encontrado ou vazio. Execute fase 9 antes."
        return
    fi

    local js_out="${BASE_DIR}/js_secrets.txt"
    > "$js_out"

    local js_urls
    js_urls=$(grep -iE '\.js(\?|$)' "$urls_file" | sort -u || true)
    local js_c; js_c=$(echo "$js_urls" | grep -c '.' 2>/dev/null || echo 0)

    _info "${js_c} arquivos JavaScript encontrados para análise."

    if [[ "$js_c" -eq 0 ]]; then
        _skip "Nenhum arquivo JS para analisar."
        return
    fi

    # Patterns de secrets — cobrem as exposições mais comuns em JS de produção
    local patterns=(
        'api[_-]?key[[:space:]]*[:=][[:space:]]*["\x27]?[a-zA-Z0-9_\-]{20,}'
        'secret[[:space:]]*[:=][[:space:]]*["\x27][a-zA-Z0-9_\-]{20,}'
        'password[[:space:]]*[:=][[:space:]]*["\x27][^"\x27\s]{8,}'
        'token[[:space:]]*[:=][[:space:]]*["\x27][a-zA-Z0-9_.\-]{20,}'
        'AKIA[0-9A-Z]{16}'
        'sk_live_[a-zA-Z0-9]{24,}'
        'pk_live_[a-zA-Z0-9]{24,}'
        'AIzaSy[a-zA-Z0-9_-]{33}'
        'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'
        'ghp_[a-zA-Z0-9]{36}'
        'gho_[a-zA-Z0-9]{36}'
        'xox[baprs]-[a-zA-Z0-9\-]+'
        'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}'
        'AC[a-z0-9]{32}'
        'SK[a-z0-9]{32}'
        'mongodb(\+srv)?://[^[:space:]"]+'
        'postgres://[^[:space:]]+'
        'mysql://[^[:space:]]+'
    )

    local dl=0 secrets_found=0

    _info "Baixando e analisando arquivos JS..."
    echo

    while IFS= read -r js_url; do
        [[ -z "$js_url" ]] && continue

        local tmp; tmp=$(mktemp /tmp/bbr_js_XXXX.js)
        curl -sk --max-time 10 "$js_url" -o "$tmp" 2>/dev/null || { rm -f "$tmp"; continue; }
        [[ ! -s "$tmp" ]] && { rm -f "$tmp"; continue; }

        printf "  ${DIM}[%3d]${RESET} %-55s " "$dl" "${js_url:0:55}"

        local found_in_file=0
        for pat in "${patterns[@]}"; do
            local match
            match=$(grep -oiE "$pat" "$tmp" 2>/dev/null | head -3 || true)
            if [[ -n "$match" ]]; then
                [[ $found_in_file -eq 0 ]] && printf "${R}SECRET!${RESET}\n"
                echo "=== ${js_url} ===" >> "$js_out"
                echo "$match" >> "$js_out"
                echo >> "$js_out"
                echo "$match" | while IFS= read -r m; do
                    _crit "SECRET em JS: ${m:0:80}"
                done
                ((found_in_file++)); ((secrets_found++))
            fi
        done
        [[ $found_in_file -eq 0 ]] && printf "${DIM}ok${RESET}\n"

        rm -f "$tmp"
        ((dl++))
        [[ $dl -ge 50 ]] && { echo; _warn "Limitando a 50 arquivos JS."; break; }
    done <<< "$js_urls"

    COUNT_SECRETS=$secrets_found
    echo
    if [[ $secrets_found -gt 0 ]]; then
        _crit "${secrets_found} SECRET(S) ENCONTRADO(S) → js_secrets.txt"
    else
        _ok "Nenhum secret detectado nos ${dl} arquivos JS analisados."
    fi

    _log "PHASE 10 concluída — ${dl} JS analisados, ${secrets_found} secrets"
    _ok "JS analysis concluído → js_secrets.txt"
}

# ==============================================================================
#  PHASE 11 — SUBDOMAIN TAKEOVER CHECK
#  Verifica se subdomínios apontam para serviços externos não reclamados
#  (GitHub Pages, Heroku, S3, Zendesk, etc).
#  Usa subzy se disponível; fallback manual por fingerprint de página.
# ==============================================================================
phase_takeover() {
    _phase "11" "SUBDOMAIN TAKEOVER CHECK"
    _confirm_phase "Takeover" || { _skip "Fase ignorada pelo operador."; return; }

    local sub_file="${BASE_DIR}/subdomains_raw.txt"
    if [[ ! -f "$sub_file" ]] || [[ ! -s "$sub_file" ]]; then
        _warn "subdomains_raw.txt não encontrado. Execute fase 3 antes."
        return
    fi

    local take_out="${BASE_DIR}/takeover_findings.txt"
    > "$take_out"

    _info "Verificando $(wc -l < "$sub_file") subdomínios para takeover..."

    if _has subzy; then
        _tool_box "subzy" "$TARGET" \
            "Subdomain takeover fingerprint" \
            "subzy run --targets subdomains_raw.txt"

        "$(_which subzy)" run --targets "$sub_file" \
            --concurrency 20 --hide-fails \
            --output "$take_out" 2>/dev/null || true

        if [[ -s "$take_out" ]] && grep -qi "VULNERABLE" "$take_out" 2>/dev/null; then
            _crit "SUBDOMAIN TAKEOVER DETECTADO!"
            grep -i "VULNERABLE" "$take_out" | while IFS= read -r line; do
                printf "    ${BOLD}${R}►${RESET} %s\n" "$line"
            done
        else
            _ok "subzy: nenhum takeover detectado."
            printf "  ${DIM}(resultado completo → takeover_findings.txt)${RESET}\n"
        fi
        return
    fi

    # ── Fallback: verificação manual por fingerprint de página ────────────────
    # Serviços externos retornam páginas características quando o recurso
    # foi deletado mas o CNAME ainda aponta para eles.
    _skip "subzy ausente. Verificação manual de CNAMEs órfãos..."
    _info "Instale: go install github.com/PentestPad/subzy@latest"
    echo

    local signatures=(
        "There is no app configured at that hostname"   # Heroku
        "No such app"                                    # Heroku
        "Repository not found"                           # GitHub Pages
        "The site configured at this address"            # GitHub Pages
        "No Such Bucket"                                 # S3
        "NoSuchBucket"                                   # S3
        "Domain is not configured"                       # Fastly
        "This page does not exist"                       # Tumblr
        "Help Center Closed"                             # Zendesk
        "Oops! That page doesn't exist"                  # Ghost
        "fastly error"                                   # Fastly
        "default.html"                                   # Azure
    )

    local check_count=0 vuln_count=0
    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue

        local cname
        cname=$(dig +short CNAME "$sub" 2>/dev/null | sed 's/\.$//' | head -1 || true)
        [[ -z "$cname" ]] && continue

        printf "  ${DIM}[%3d]${RESET} %-45s → ${C}%s${RESET}" "$check_count" "$sub" "$cname"

        local page
        page=$(curl -sk --max-time 8 "https://${sub}" 2>/dev/null || true)

        local found=0
        for sig in "${signatures[@]}"; do
            if echo "$page" | grep -qi "$sig"; then
                printf " ${BOLD}${R}VULNERABLE!${RESET}\n"
                echo "VULNERABLE: ${sub} → CNAME: ${cname} (${sig})" >> "$take_out"
                ((found++)); ((vuln_count++))
                break
            fi
        done
        [[ $found -eq 0 ]] && printf " ${DIM}ok${RESET}\n"

        ((check_count++))
        [[ $check_count -ge 50 ]] && { echo; _warn "Limitando a 50 subdomínios."; break; }
    done < "$sub_file"

    echo
    if [[ $vuln_count -gt 0 ]]; then
        _crit "${vuln_count} POSSÍVEL(IS) TAKEOVER(S) DETECTADO(S) → takeover_findings.txt"
    else
        _ok "Nenhum takeover detectado nos ${check_count} subdomínios verificados."
    fi

    _log "PHASE 11 concluída"
    _ok "Takeover check concluído → takeover_findings.txt"
}

# ==============================================================================
#  PHASE 12 — VULNERABILITY SCAN (nuclei)
#  Roda templates do nuclei para CVEs conhecidos, misconfigs, default-logins
#  e exposições comuns. Ordena resultados por severidade.
# ==============================================================================
phase_nuclei() {
    _phase "12" "VULNERABILITY SCAN — nuclei"
    _confirm_phase "nuclei" || { _skip "Fase ignorada pelo operador."; return; }

    if ! _has nuclei; then
        _skip "nuclei ausente."
        _info "Instale: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        return
    fi

    local alive_file="${BASE_DIR}/subdomains_alive.txt"
    [[ ! -f "$alive_file" ]] || [[ ! -s "$alive_file" ]] && {
        _warn "subdomains_alive.txt não encontrado. Execute fase 3 antes."
        return
    }

    # Extrai URLs limpas do arquivo de hosts vivos
    local urls_tmp="${BASE_DIR}/.nuclei_urls.tmp"
    grep -oE 'https?://[^ ]+' "$alive_file" | sort -u > "$urls_tmp" || true

    local uc; uc=$(wc -l < "$urls_tmp" 2>/dev/null || echo 0)
    _tool_box "nuclei" "$TARGET" \
        "CVE + misconfig + exposure + default-login" \
        "nuclei -l alive.txt -tags cve,misconfig,exposure,default-login"

    local nuc_out="${BASE_DIR}/nuclei_findings.txt"

    "$(_which nuclei)" \
        -l "$urls_tmp" \
        -tags "cve,exposure,misconfig,default-login,takeover,tech" \
        -severity "low,medium,high,critical" \
        -c 25 -timeout 10 \
        -o "$nuc_out" -silent 2>/dev/null || true

    rm -f "$urls_tmp"

    echo
    if [[ ! -s "$nuc_out" ]]; then
        _ok "nuclei: nenhum finding detectado nos ${uc} hosts."
        return
    fi

    local total; total=$(wc -l < "$nuc_out")
    _ok "${total} finding(s) nuclei"

    # Exibe resultados separados por severidade — do mais crítico ao mais baixo
    for sev in critical high medium low info; do
        local lines
        lines=$(grep -i "\[${sev}\]" "$nuc_out" 2>/dev/null || true)
        [[ -z "$lines" ]] && continue

        local cnt; cnt=$(echo "$lines" | wc -l)

        case "$sev" in
            critical)
                _crit "${cnt} FINDING(S) CRITICAL:"
                echo "$lines" | sed 's/^/    /'
                COUNT_NUCLEI_CRIT=$cnt
                ;;
            high)
                echo
                printf " ${BOLD}${R}  ◉ HIGH (%d findings)${RESET}\n" "$cnt"
                echo "$lines" | sed 's/^/    /'
                COUNT_NUCLEI_HIGH=$cnt
                ;;
            medium)
                echo
                printf " ${Y}  ▲ MEDIUM (%d findings)${RESET}\n" "$cnt"
                echo "$lines" | sed 's/^/    /'
                ;;
            low)
                echo
                printf " ${C}  ℹ LOW (%d findings)${RESET}\n" "$cnt"
                echo "$lines" | head -5 | sed 's/^/    /'
                [[ $cnt -gt 5 ]] && printf "    ${DIM}... (+%d more → nuclei_findings.txt)${RESET}\n" $(( cnt - 5 ))
                ;;
            info)
                printf " ${DIM}  ℹ INFO (%d findings → nuclei_findings.txt)${RESET}\n" "$cnt"
                ;;
        esac
    done

    echo
    _log "PHASE 12 concluída — ${total} nuclei findings"
    _ok "nuclei concluído → nuclei_findings.txt"
}

# ==============================================================================
#  PHASE 13 — WEB AUDIT (nikto)
#  Auditoria web em cima dos hosts mais interessantes.
#  Limitado a 5 hosts para não tornar a operação excessivamente longa.
#  Foca em misconfigs HTTP, arquivos expostos e CVEs conhecidos por banner.
# ==============================================================================
phase_nikto() {
    _phase "13" "WEB AUDIT — nikto"
    _confirm_phase "nikto" || { _skip "Fase ignorada pelo operador."; return; }

    if ! _has nikto; then
        _skip "nikto ausente. Instale: sudo apt install nikto"
        return
    fi

    [[ ${#ALIVE_HOSTS[@]} -eq 0 ]] && { _warn "Nenhum host vivo."; return; }

    local nikto_out="${BASE_DIR}/nikto.txt"
    > "$nikto_out"
    local count=0

    # Prioriza hosts marcados como interessantes (painéis, serviços críticos)
    local targets=()
    [[ -s "${BASE_DIR}/subdomains_interesting.txt" ]] && \
        while IFS= read -r line; do
            local url
            url=$(echo "$line" | grep -oE 'https?://[^ ]+' | head -1 || true)
            [[ -n "$url" ]] && targets+=("$url")
        done < "${BASE_DIR}/subdomains_interesting.txt"

    # Complementa com hosts vivos se não tiver 5 ainda
    for h in "${ALIVE_HOSTS[@]}"; do
        [[ ${#targets[@]} -ge 5 ]] && break
        local already=0
        for t in "${targets[@]}"; do [[ "$t" == "$h" ]] && already=1 && break; done
        [[ $already -eq 0 ]] && targets+=("$h")
    done

    _info "Auditando ${#targets[@]} host(s) prioritários..."

    for host in "${targets[@]}"; do
        local domain
        domain=$(echo "$host" | grep -oP '(?<=://)([^/:]+)' || true)
        [[ -z "$domain" ]] && continue

        _tool_box "nikto" "$host" \
            "Auditoria HTTP: misconfigs, headers, arquivos expostos" \
            "nikto -h ${host} -Tuning 0126789abc"

        echo "=== ${host} ===" >> "$nikto_out"
        local scan
        scan=$(timeout 120 "$(_which nikto)" -h "$host" \
            -Tuning "0126789abc" -timeout 10 -nointeractive \
            2>/dev/null || true)

        echo "$scan" >> "$nikto_out"

        # Exibe apenas linhas que indicam findings reais
        local findings
        findings=$(echo "$scan" \
            | grep -iE 'OSVDB|CVE|XSS|SQL|inject|LFI|RFI|RCE|traverse|shell|backdoor|interesting|exposed|dangerous|default|password|cleartext' \
            | grep -v '^-' \
            | grep -v 'Start Time' \
            2>/dev/null || true)

        if [[ -n "$findings" ]]; then
            _find "nikto findings em ${domain}:"
            echo "$findings" | while IFS= read -r f; do
                echo "$f" | grep -qiE 'CVE|OSVDB|inject|XSS|RCE|shell' \
                    && _crit "nikto: ${f}" \
                    || printf "    ${Y}►${RESET} %s\n" "$f"
            done
        else
            _skip "nikto: sem findings críticos em ${domain}"
        fi

        ((count++))
        [[ $count -ge 5 ]] && { _warn "Limite de 5 hosts atingido."; break; }
    done

    echo
    _log "PHASE 13 concluída"
    _ok "nikto concluído → nikto.txt"
}

# ==============================================================================
#  SUMMARY — RELATÓRIO OPERACIONAL FINAL
#  Consolida todos os findings em um relatório estruturado por severidade.
#  Fornece ações concretas baseadas nos achados para o próximo passo.
# ==============================================================================
_summary() {
    echo
    _sep2
    printf "\n ${BOLD}${G}▶▶  OPERATIONAL SUMMARY — %s${RESET}\n\n" "$TARGET"
    _sep2
    echo

    # ── Estatísticas gerais ───────────────────────────────────────────────────
    local sub_c alive_c ip_c url_c email_c
    sub_c=$(wc -l < "${BASE_DIR}/subdomains_raw.txt"   2>/dev/null || echo "${COUNT_SUBDOMAINS:-0}")
    alive_c=$(wc -l < "${BASE_DIR}/subdomains_alive.txt" 2>/dev/null || echo "${COUNT_ALIVE:-0}")
    ip_c=$(wc -l < "${BASE_DIR}/unique_ips.txt"         2>/dev/null || echo "${COUNT_IPS:-0}")
    url_c=$(wc -l < "${BASE_DIR}/urls_final.txt"        2>/dev/null || echo "${COUNT_URLS:-0}")
    email_c=$(wc -l < "${BASE_DIR}/emails.txt"          2>/dev/null || echo 0)

    printf "  ${BOLD}RECON STATISTICS${RESET}\n\n"
    printf "  ${DIM}%-28s${RESET}  ${W}%s${RESET}\n" "Alvo:"               "$TARGET"
    printf "  ${DIM}%-28s${RESET}  ${W}%s${RESET}\n" "Subdomínios brutos:" "$sub_c"
    printf "  ${DIM}%-28s${RESET}  ${W}%s${RESET}\n" "Hosts vivos:"        "$alive_c"
    printf "  ${DIM}%-28s${RESET}  ${W}%s${RESET}\n" "IPs únicos:"         "$ip_c"
    printf "  ${DIM}%-28s${RESET}  ${W}%s${RESET}\n" "URLs coletadas:"     "$url_c"
    printf "  ${DIM}%-28s${RESET}  ${W}%s${RESET}\n" "Emails coletados:"   "$email_c"
    printf "  ${DIM}%-28s${RESET}  ${W}%s${RESET}\n" "Tempo total:"        "$(_elapsed)"
    echo
    _sep
    echo

    local findings_count=0

    # ── CRITICAL FINDINGS ─────────────────────────────────────────────────────
    printf "  ${BOLD}${R}CRITICAL FINDINGS${RESET}\n\n"

    # Zone Transfer
    if ls "${BASE_DIR}"/axfr_*.txt &>/dev/null 2>&1; then
        _crit "ZONE TRANSFER POSSÍVEL — infraestrutura interna exposta"
        printf "    ${DIM}Ação: documentar todos os registros e incluir no relatório como crítico${RESET}\n\n"
        ((findings_count++))
    fi

    # Subdomain Takeover
    if [[ -s "${BASE_DIR}/takeover_findings.txt" ]] && \
       grep -qi "VULNERABLE" "${BASE_DIR}/takeover_findings.txt" 2>/dev/null; then
        _crit "SUBDOMAIN TAKEOVER CONFIRMADO"
        grep -i "VULNERABLE" "${BASE_DIR}/takeover_findings.txt" | sed 's/^/    /'
        printf "\n    ${DIM}Ação: reclamar o recurso ou remover o CNAME imediatamente${RESET}\n\n"
        ((findings_count++))
    fi

    # Nuclei Critical
    if [[ $COUNT_NUCLEI_CRIT -gt 0 ]] || \
       { [[ -s "${BASE_DIR}/nuclei_findings.txt" ]] && \
         grep -qi '\[critical\]' "${BASE_DIR}/nuclei_findings.txt" 2>/dev/null; }; then
        _crit "VULNERABILIDADES CRÍTICAS — nuclei"
        grep -i '\[critical\]' "${BASE_DIR}/nuclei_findings.txt" 2>/dev/null | head -10 | sed 's/^/    /'
        printf "\n    ${DIM}Ação: exploração manual imediata em ambiente controlado${RESET}\n\n"
        ((findings_count++))
    fi

    # JS Secrets
    if [[ -s "${BASE_DIR}/js_secrets.txt" ]]; then
        _crit "SECRETS EXPOSTOS EM JAVASCRIPT"
        head -10 "${BASE_DIR}/js_secrets.txt" | sed 's/^/    /'
        printf "\n    ${DIM}Ação: revogar credenciais imediatamente + notificar cliente${RESET}\n\n"
        ((findings_count++))
    fi

    # Portas críticas
    if [[ ${#CRIT_PORTS_FOUND[@]} -gt 0 ]]; then
        _crit "PORTAS CRÍTICAS ABERTAS"
        for cp in "${CRIT_PORTS_FOUND[@]}"; do
            printf "    ${BOLD}${R}►${RESET} %s\n" "$cp"
        done
        printf "\n    ${DIM}Ação: verificar necessidade de exposição + testar autenticação${RESET}\n\n"
        ((findings_count++))
    fi

    # ── HIGH / MEDIUM FINDINGS ────────────────────────────────────────────────
    _sep
    echo
    printf "  ${BOLD}${Y}HIGH / MEDIUM FINDINGS${RESET}\n\n"

    # Nuclei High
    if [[ $COUNT_NUCLEI_HIGH -gt 0 ]] || \
       { [[ -s "${BASE_DIR}/nuclei_findings.txt" ]] && \
         grep -qi '\[high\]' "${BASE_DIR}/nuclei_findings.txt" 2>/dev/null; }; then
        _warn "VULNERABILIDADES HIGH — nuclei"
        grep -i '\[high\]' "${BASE_DIR}/nuclei_findings.txt" 2>/dev/null | head -5 | sed 's/^/    /'
        echo
        ((findings_count++))
    fi

    # Painéis admin detectados
    if [[ ${#PANELS_FOUND[@]} -gt 0 ]]; then
        _warn "PAINÉIS ADMINISTRATIVOS EXPOSTOS (${#PANELS_FOUND[@]})"
        for p in "${PANELS_FOUND[@]}"; do
            printf "    ${Y}►${RESET} %s\n" "${p:0:80}"
        done
        echo
        ((findings_count++))
    fi

    # WAFs detectados
    if [[ ${#WAFS_FOUND[@]} -gt 0 ]]; then
        _warn "WAF detectado em ${#WAFS_FOUND[@]} host(s) — considere técnicas de evasão"
        for w in "${WAFS_FOUND[@]}"; do
            printf "    ${Y}►${RESET} %s\n" "$w"
        done
        echo
        ((findings_count++))
    fi

    # TLS fraco
    if [[ -s "${BASE_DIR}/ssl.txt" ]] && \
       grep -qiE "SSLv[23]|TLSv1\.0.*enabled|RC4|NULL|EXPORT" "${BASE_DIR}/ssl.txt" 2>/dev/null; then
        _warn "PROTOCOLO TLS INSEGURO DETECTADO → ssl.txt"
        echo
        ((findings_count++))
    fi

    # ── INFORMATIONAL ─────────────────────────────────────────────────────────
    _sep
    echo
    printf "  ${BOLD}${C}INFORMATIONAL${RESET}\n\n"

    [[ $email_c -gt 0 ]] && {
        _ok "${email_c} emails coletados → emails.txt"
        _note "Usar para campanhas de phishing, password spray, OSINT aprofundado"
        echo
    }

    [[ "$url_c" -gt 0 ]] && {
        local api_c params_c
        api_c=$(grep -ciE '/api/|/v[0-9]+/|/rest/|/graphql' "${BASE_DIR}/urls_final.txt" 2>/dev/null || echo 0)
        params_c=$(grep -cE '(\?|&)[a-zA-Z0-9_]+=.+' "${BASE_DIR}/urls_final.txt" 2>/dev/null || echo 0)
        [[ $api_c -gt 0 ]]    && { _ok "${api_c} endpoints de API encontrados";    _note "Testar autenticação, autorização, IDOR"; echo; }
        [[ $params_c -gt 0 ]] && { _ok "${params_c} URLs com parâmetros";          _note "Testar SQLi, XSS, SSRF, LFI manualmente"; echo; }
    }

    [[ $findings_count -eq 0 ]] && \
        _info "Nenhum finding crítico automático. Revisão manual dos arquivos recomendada."

    # ── Files gerados ─────────────────────────────────────────────────────────
    echo
    _sep
    echo
    printf "  ${BOLD}ARQUIVOS GERADOS${RESET}\n\n"
    for f in \
        subdomains_raw.txt subdomains_alive.txt subdomains_interesting.txt \
        unique_ips.txt emails.txt waf.txt nmap.txt nmap_critical.txt \
        ssl.txt gobuster.txt urls_final.txt js_secrets.txt \
        takeover_findings.txt nuclei_findings.txt nikto.txt; do
        local fp="${BASE_DIR}/${f}"
        if [[ -f "$fp" ]] && [[ -s "$fp" ]]; then
            local lc; lc=$(wc -l < "$fp" 2>/dev/null || echo "?")
            printf "  ${G}  %-36s${RESET}  ${DIM}%s linhas${RESET}\n" "$f" "$lc"
        fi
    done

    echo
    _sep
    printf "  ${DIM}Output dir:  ${BOLD}%s/${RESET}\n" "$BASE_DIR"
    printf "  ${DIM}Log:         ${BOLD}%s/recon.log${RESET}\n" "$BASE_DIR"
    _sep
    echo
}

# ==============================================================================
#  USAGE
# ==============================================================================
_usage() {
    cat << EOF

  ${BOLD}USAGE:${RESET}
    $(basename "$0") [OPTIONS]

  ${BOLD}OPTIONS:${RESET}
    -d DOMAIN     Domínio alvo (ex: target.com)
    -y            Pular todas as confirmações de fase
    -p PHASE      Executar apenas uma fase específica (1–13)
    -h            Exibir esta ajuda

  ${BOLD}EXEMPLOS:${RESET}
    $(basename "$0") -d target.com
    $(basename "$0") -d target.com -y
    $(basename "$0") -d target.com -p 3

  ${BOLD}FASES:${RESET}
    1  WHOIS + DNS          7  SSL/TLS
    2  OSINT passivo        8  Directory Enum
    3  Subdomains + Filter  9  URL Collection
    4  WAF Detection       10  JS Secrets
    5  Fingerprinting      11  Takeover Check
    6  Port Scan           12  nuclei
                           13  nikto

EOF
}

# ==============================================================================
#  MAIN
# ==============================================================================
main() {
    while getopts "d:yp:h" opt; do
        case "$opt" in
            d) TARGET="$OPTARG"  ;;
            y) SKIP_CONFIRM=1    ;;
            p) PHASE_ONLY="$OPTARG" ;;
            h) _banner; _usage; exit 0 ;;
            *) _usage; exit 1   ;;
        esac
    done

    _banner

    # Solicita domínio interativamente se não passado via -d
    if [[ -z "$TARGET" ]]; then
        printf "  ${C}Target domain:${RESET} "
        read -r TARGET || true
        [[ -z "$TARGET" ]] && { _err "Domínio não pode ser vazio."; exit 1; }
    fi

    # Sanitiza: lowercase, remove protocolo e trailing slash
    TARGET="${TARGET,,}"
    TARGET="${TARGET#http://}"
    TARGET="${TARGET#https://}"
    TARGET="${TARGET%%/*}"

    START_TS=$(date +%s)
    _info "Alvo: ${BOLD}${TARGET}${RESET}"
    echo

    _check_deps
    _setup_dirs
    _log "=== Recon iniciado: ${TARGET} ==="

    # Executa fase única ou fluxo completo
    if [[ -n "$PHASE_ONLY" ]]; then
        case "$PHASE_ONLY" in
            1)  phase_whois_dns  ;;
            2)  phase_osint      ;;
            3)  phase_subdomains ;;
            4)  phase_waf        ;;
            5)  phase_fingerprint ;;
            6)  phase_nmap       ;;
            7)  phase_ssl        ;;
            8)  phase_gobuster   ;;
            9)  phase_urls       ;;
            10) phase_js         ;;
            11) phase_takeover   ;;
            12) phase_nuclei     ;;
            13) phase_nikto      ;;
            *)  _err "Fase inválida: ${PHASE_ONLY} (use 1–13)"; exit 1 ;;
        esac
    else
        phase_whois_dns
        phase_osint
        phase_subdomains
        phase_waf
        phase_fingerprint
        phase_nmap
        phase_ssl
        phase_gobuster
        phase_urls
        phase_js
        phase_takeover
        phase_nuclei
        phase_nikto
    fi

    _summary
    _log "=== Recon concluído em $(_elapsed) ==="
}

main "$@"
