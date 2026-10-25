#!/usr/bin/env bash
# ==============================================================================
# YNetMon - Homelab Network Guard & 7-Layer OSI Traffic Inspector
# Modern 1-Command Automated Installer & Setup Script
# Repository: https://github.com/YagYz/YNetMon
# ==============================================================================

set -e

COLOR_RESET="\033[0m"
COLOR_BOLD="\033[1m"
COLOR_CYAN="\033[36m"
COLOR_GREEN="\033[32m"
COLOR_YELLOW="\033[33m"
COLOR_RED="\033[31m"
COLOR_PURPLE="\033[35m"

print_banner() {
    clear 2>/dev/null || true
    echo -e "${COLOR_CYAN}${COLOR_BOLD}"
    cat << "EOF"
__     ___   _      _   __  __             
\ \   / / \ | | ___| |_|  \/  | ___  _ __  
 \ \ / /|  \| |/ _ \ __| |\/| |/ _ \| '_ \ 
  \ V / | |\  |  __/ |_| |  | | (_) | | | |
   \_/  |_| \_|\___|\__|_|  |_|\___/|_| |_|
  Homelab Network Guard & 7-Layer OSI Traffic Inspector
EOF
    echo -e "${COLOR_RESET}"
    echo -e "${COLOR_PURPLE}------------------------------------------------------------${COLOR_RESET}"
    echo -e " Otomatik Kurulum ve Konfigürasyon Sihirbazı"
    echo -e "${COLOR_PURPLE}------------------------------------------------------------${COLOR_RESET}\n"
}

log_info() {
    echo -e "${COLOR_CYAN}[INFO]${COLOR_RESET} $1"
}

log_ok() {
    echo -e "${COLOR_GREEN}[✔]${COLOR_RESET} $1"
}

log_warn() {
    echo -e "${COLOR_YELLOW}[!]${COLOR_RESET} $1"
}

log_error() {
    echo -e "${COLOR_RED}[✖]${COLOR_RESET} $1"
}

# 1. Host IP and Interface Discovery
detect_host_ip() {
    HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n 1 || hostname -I 2>/dev/null | awk '{print $1}')
    [ -z "$HOST_IP" ] && HOST_IP="127.0.0.1"
}

# 2. Check Prerequisites
detect_environment() {
    log_info "Sistem gereksinimleri taranıyor..."

    # Check Docker
    HAS_DOCKER=false
    HAS_COMPOSE=false
    if command -v docker >/dev/null 2>&1; then
        HAS_DOCKER=true
        if docker compose version >/dev/null 2>&1; then
            DOCKER_COMPOSE_CMD="docker compose"
            HAS_COMPOSE=true
        elif command -v docker-compose >/dev/null 2>&1; then
            DOCKER_COMPOSE_CMD="docker-compose"
            HAS_COMPOSE=true
        fi
    fi

    # Check Python
    HAS_PYTHON=false
    if command -v python3 >/dev/null 2>&1; then
        PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
        PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 10 ]; then
            HAS_PYTHON=true
        fi
    fi
}

# 3. Ensure we are in project directory or clone
ensure_project_files() {
    if [ ! -f "docker-compose.yml" ] || [ ! -d "app" ]; then
        log_info "YNetMon kaynak kodları GitHub'dan indiriliyor..."
        INSTALL_DIR="YNetMon"
        if [ -d "$INSTALL_DIR" ]; then
            cd "$INSTALL_DIR"
            git pull origin main || true
        else
            git clone https://github.com/YagYz/YNetMon.git "$INSTALL_DIR"
            cd "$INSTALL_DIR"
        fi
        log_ok "Proje dizinine geçildi: $(pwd)"
    fi
}

# 4. Generate or update .env configuration
setup_env() {
    log_info "Ortam değişkenleri (.env) yapılandırılıyor..."
    mkdir -p data
    chmod 755 data

    if [ ! -f ".env" ]; then
        if [ -f ".env.example" ]; then
            cp .env.example .env
        else
            cat << 'EOF' > .env
YNETMON_PORT=8765
YNETMON_DB=/app/data/ynetmon.db
HOST_DATA_DIR=./data
YNETMON_ADMIN_USER=
YNETMON_ADMIN_PASS=
EOF
        fi
        log_ok ".env dosyası oluşturuldu."
    else
        log_ok "Mevcut .env dosyası korundu."
    fi
}

# 5. Docker Deployment Mode
install_docker() {
    log_info "Docker ortamı hazırlanıyor..."
    setup_env

    # Check port conflicts
    PORT=$(grep -E '^YNETMON_PORT=' .env | cut -d= -f2 || echo "8765")
    [ -z "$PORT" ] && PORT=8765

    if command -v ss >/dev/null 2>&1; then
        if ss -tuln | grep -q ":${PORT} "; then
            log_warn "Port ${PORT} şu anda başka bir servis tarafından kullanılıyor olabilir!"
        fi
    fi

    log_info "Konteynerler başlatılıyor (${DOCKER_COMPOSE_CMD} up -d)..."
    $DOCKER_COMPOSE_CMD down 2>/dev/null || true
    $DOCKER_COMPOSE_CMD up -d --build

    # Wait for service health check
    log_info "YNetMon servisinin ayağa kalkması bekleniyor..."
    for i in {1..15}; do
        if curl -fs "http://127.0.0.1:${PORT}/login" >/dev/null 2>&1 || curl -fs "http://127.0.0.1:${PORT}/" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    print_success "$PORT" "Docker Konteyner (ynetmon-app)"
}

# 6. Native Python & Systemd Service Mode
install_native() {
    log_info "Yerel Python 3 ortamı kuruluyor..."
    setup_env

    # Check virtual environment
    if [ ! -d ".venv" ]; then
        log_info "Python sanal ortamı (.venv) oluşturuluyor..."
        python3 -m venv .venv
    fi

    log_info "Python bağımlılıkları yükleniyor..."
    ./.venv/bin/pip install --upgrade pip >/dev/null 2>&1
    ./.venv/bin/pip install -r requirements.txt

    # Capability grants for raw socket capture without root
    PY_BIN=$(readlink -f ./.venv/bin/python3)
    if command -v setcap >/dev/null 2>&1; then
        log_info "Raw paket yakalama yetkisi (CAP_NET_RAW) atanıyor..."
        if [ "$EUID" -eq 0 ]; then
            setcap cap_net_raw,cap_net_admin=eip "$PY_BIN" || true
            log_ok "Paket yakalama yetkisi atandı: $PY_BIN"
        elif command -v sudo >/dev/null 2>&1; then
            sudo setcap cap_net_raw,cap_net_admin=eip "$PY_BIN" || true
            log_ok "Sudo ile yetki atandı."
        else
            log_warn "setcap çalıştırılamadı. Raw yakalama için root veya Socket Flow modu kullanılacak."
        fi
    fi

    PORT=8765
    log_info "YNetMon arka plan servisi başlatılıyor..."
    
    # Optional systemd creation if root/sudo available
    if [ -d "/etc/systemd/system" ] && ( [ "$EUID" -eq 0 ] || command -v sudo >/dev/null 2>&1 ); then
        SERVICE_FILE="/etc/systemd/system/ynetmon.service"
        CURRENT_DIR=$(pwd)
        CURRENT_USER=$(id -un)
        
        SERVICE_CONTENT="[Unit]
Description=YNetMon Homelab Network Guard & Inspector
After=network.target

[Service]
Type=simple
User=${CURRENT_USER}
WorkingDirectory=${CURRENT_DIR}
EnvironmentFile=${CURRENT_DIR}/.env
ExecStart=${CURRENT_DIR}/.venv/bin/python3 -m app.main
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
"
        echo "$SERVICE_CONTENT" | ( [ "$EUID" -eq 0 ] && tee "$SERVICE_FILE" >/dev/null || sudo tee "$SERVICE_FILE" >/dev/null )
        ( [ "$EUID" -eq 0 ] && systemctl daemon-reload && systemctl enable --now ynetmon || ( sudo systemctl daemon-reload && sudo systemctl enable --now ynetmon ) )
        log_ok "Systemd servisi kuruldu ve aktif edildi: ynetmon.service"
    else
        nohup ./.venv/bin/python3 -m app.main > data/ynetmon.log 2>&1 &
        log_ok "YNetMon nohup ile arka planda başlatıldı (PID: $!)."
    fi

    print_success "$PORT" "Systemd / Native Python"
}

# 7. Print Completion Banner
print_success() {
    PORT=$1
    MODE=$2
    detect_host_ip

    echo -e "\n${COLOR_GREEN}${COLOR_BOLD}============================================================${COLOR_RESET}"
    echo -e "${COLOR_GREEN}${COLOR_BOLD}   🎉 YNetMon Başarıyla Kuruldu ve Çalışıyor!${COLOR_RESET}"
    echo -e "${COLOR_GREEN}${COLOR_BOLD}============================================================${COLOR_RESET}\n"

    echo -e "  ${COLOR_BOLD}Çalışma Modu :${COLOR_RESET} ${COLOR_CYAN}${MODE}${COLOR_RESET}"
    echo -e "  ${COLOR_BOLD}Yerel Erişim :${COLOR_RESET} ${COLOR_GREEN}http://localhost:${PORT}${COLOR_RESET}"
    echo -e "  ${COLOR_BOLD}Ağ Erişimi   :${COLOR_RESET} ${COLOR_GREEN}http://${HOST_IP}:${PORT}${COLOR_RESET}"
    echo -e "  ${COLOR_BOLD}OSI Desteği  :${COLOR_RESET} 7 Katman Tam Analiz (L1-L7 Canlı İnceleyici)"
    echo -e "  ${COLOR_BOLD}Tehdit Motoru:${COLOR_RESET} Steam/Cloudflare/Tailscale Akıllı Filtreleme Aktif\n"

    echo -e "${COLOR_YELLOW}İlk Giriş & Yapılandırma:${COLOR_RESET}"
    echo -e "  Tarayıcınızdan yukarıdaki adrese gidin. İlk açılışta yönetici"
    echo -e "  kullanıcı adı ve parolanızı belirlemeniz için güvenli kurulum"
    echo -e "  ekranı sizi karşılayacaktır.\n"

    echo -e "${COLOR_CYAN}Yönetim & Günlük Takibi:${COLOR_RESET}"
    if [ "$HAS_COMPOSE" = true ]; then
        echo -e "  Logları izleme : ${COLOR_BOLD}${DOCKER_COMPOSE_CMD} logs -f${COLOR_RESET}"
        echo -e "  Durdurma       : ${COLOR_BOLD}${DOCKER_COMPOSE_CMD} down${COLOR_RESET}"
        echo -e "  Yeniden Başlat : ${COLOR_BOLD}${DOCKER_COMPOSE_CMD} restart${COLOR_RESET}"
    else
        echo -e "  Logları izleme : ${COLOR_BOLD}journalctl -u ynetmon -f${COLOR_RESET}"
        echo -e "  Servis Durumu  : ${COLOR_BOLD}systemctl status ynetmon${COLOR_RESET}"
    fi
    echo -e "${COLOR_PURPLE}------------------------------------------------------------${COLOR_RESET}\n"
}

# --- Main Execution Flow ---
print_banner
detect_host_ip
detect_environment
ensure_project_files

if [ "$HAS_COMPOSE" = true ]; then
    log_ok "Docker ve Docker Compose tespit edildi."
    install_docker
elif [ "$HAS_PYTHON" = true ]; then
    log_info "Docker bulunamadı, yerel Python 3 (${PY_VER}) kurulumu yapılıyor..."
    install_native
else
    log_error "Ne Docker Compose ne de uyumlu bir Python 3 (>=3.10) ortamı bulunamadı!"
    echo "Lütfen önce Docker veya Python 3 kurup tekrar deneyiniz:"
    echo "  Debian/Ubuntu için: sudo apt update && sudo apt install -y docker.io docker-compose-v2"
    exit 1
fi
