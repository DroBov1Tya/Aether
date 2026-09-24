#!/bin/bash
set -e

# ============================================================================
#  Цвета и символы для красивого вывода
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

OK="[${GREEN}OK${NC}]"
FAIL="[${RED}FAIL${NC}]"
INFO="[${BLUE}INFO${NC}]"
WARN="[${YELLOW}WARN${NC}]"
STEP="[${CYAN}STEP${NC}]"

TOTAL_STEPS=6
CURRENT_STEP=0

# ============================================================================
#  Функции вывода
# ============================================================================
print_header() {
    echo ""
    echo -e "${BOLD}${BLUE}======================================================================${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}======================================================================${NC}"
    echo ""
}

print_step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    local progress=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    local filled=$((progress / 5))
    local empty=$((20 - filled))
    local bar=$(printf "%${filled}s" | tr ' ' '#')$(printf "%${empty}s" | tr ' ' '-')

    echo ""
    echo -e "${STEP} ${BOLD}[${bar}] ${progress}%${NC} — ${BOLD}$1${NC} (${CURRENT_STEP}/${TOTAL_STEPS})"
    echo -e "${BLUE}----------------------------------------------------------------------${NC}"
}

print_ok()    { echo -e "  ${OK} $1"; }
print_info()  { echo -e "  ${INFO} $1"; }
print_warn()  { echo -e "  ${WARN} $1"; }
print_error() { echo -e "  ${FAIL} $1"; }

# Обработка ошибок
cleanup_on_error() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo ""
        print_error "Скрипт завершился с ошибкой (код: $exit_code)"
        print_info "Попробуйте запустить повторно или проверьте логи выше."
        exit $exit_code
    fi
}
trap cleanup_on_error EXIT

# ============================================================================
#  Проверка прав root
# ============================================================================
if [ "$EUID" -ne 0 ]; then
    print_error "Скрипт должен быть запущен от имени root (используйте sudo)."
    exit 1
fi

print_header "Установка окружения для Agent"
print_info "Целевая ОС: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
print_info "Архитектура: $(uname -m)"
print_info "Время запуска: $(date '+%Y-%m-%d %H:%M:%S')"

# ============================================================================
#  Шаг 1. Починка apt (если предыдущая установка сломалась)
# ============================================================================
print_step "Проверка и починка пакетного менеджера"

if dpkg --configure -a 2>/dev/null; then
    print_ok "dpkg в рабочем состоянии"
else
    print_warn "Обнаружены незавершённые установки. Запускаем восстановление..."
    dpkg --configure -a
    apt-get --fix-broken install -y
    print_ok "Пакетный менеджер восстановлен"
fi

# Удаляем snap-chromium, если он остался от предыдущих попыток
if dpkg -l | grep -q "chromium-browser.*snap"; then
    print_warn "Удаляем snap-обёртку chromium-browser..."
    apt-get remove -y chromium-browser 2>/dev/null || true
fi

# ============================================================================
#  Шаг 2. Обновление списков пакетов
# ============================================================================
print_step "Обновление списков пакетов"

apt-get update -qq
print_ok "Списки пакетов обновлены"

# ============================================================================
#  Шаг 3. Базовые зависимости для сборки
# ============================================================================
print_step "Установка базовых зависимостей для сборки"

apt-get install -y -qq \
    curl \
    wget \
    gnupg \
    ca-certificates \
    build-essential \
    pkg-config \
    musl-tools \
    gcc-aarch64-linux-gnu \
    binutils \
    software-properties-common > /dev/null

print_ok "Инструменты сборки установлены"

# ============================================================================
#  Шаг 4. Runtime-зависимости + классический Chromium через PPA
# ============================================================================
print_step "Установка runtime-зависимостей"

print_info "Устанавливаем базовые пакеты (nmap, whatweb, dnsutils, whois, openssl)..."
apt-get install -y -qq \
    tzdata \
    nmap \
    whatweb \
    dnsutils \
    whois \
    openssl \
    bash \
    libgbm1 \
    libnss3 \
    fonts-liberation > /dev/null
print_ok "Базовые пакеты установлены"

print_info "Подключаем PPA с классическим Chromium (без snap)..."
add-apt-repository -y ppa:xtradeb/apps > /dev/null 2>&1
apt-get update -qq
print_ok "PPA ppa:xtradeb/apps подключён"

print_info "Устанавливаем классический Chromium и chromedriver..."
apt-get install -y -qq chromium chromium-driver > /dev/null
print_ok "Chromium $(chromium --version 2>/dev/null | awk '{print $2}' || echo 'установлен')"

# Создаём симлинки для совместимости
ln -sf "$(which chromium)" /usr/local/bin/chromium 2>/dev/null || true
ln -sf "$(which chromedriver)" /usr/local/bin/chromedriver 2>/dev/null || true
print_ok "Симлинки chromium и chromedriver созданы в /usr/local/bin"

# ============================================================================
#  Шаг 5. Настройка окружения и временной зоны
# ============================================================================
print_step "Настройка системного окружения"

# Временная зона
ln -snf /usr/share/zoneinfo/Europe/Moscow /etc/localtime
echo "Europe/Moscow" > /etc/timezone
print_ok "Временная зона: Europe/Moscow"

# Директория для скриншотов
mkdir -p /app/screenshots
chmod 777 /app/screenshots
print_ok "Директория /app/screenshots создана"

# Переменные окружения
cat << 'EOF' > /etc/profile.d/agent_env.sh
export RUST_LOG=info
export HOME=/tmp
export XDG_RUNTIME_DIR=/tmp
export TZ=Europe/Moscow
EOF
chmod +x /etc/profile.d/agent_env.sh
print_ok "Переменные окружения записаны в /etc/profile.d/agent_env.sh"

# ============================================================================
#  Шаг 6. Очистка кэша
# ============================================================================
print_step "Очистка кэша apt"

apt-get clean
rm -rf /var/lib/apt/lists/*
print_ok "Кэш очищен"

# ============================================================================
#  Финальный отчёт
# ============================================================================
print_header "Установка завершена успешно!"

echo -e "  ${BOLD}Установленные компоненты:${NC}"
echo -e "    • Chromium:        $(chromium --version 2>/dev/null | awk '{print $2}' || echo 'установлен')"
echo -e "    • chromedriver:    $(chromedriver --version 2>/dev/null | awk '{print $2}' || echo 'установлен')"
echo -e "    • nmap:            $(nmap --version 2>/dev/null | head -n 2 | tail -n 1 | awk '{print $NF}')"
echo -e "    • whatweb:         $(whatweb --version 2>/dev/null | awk '{print $2}' || echo 'установлен')"
echo ""
echo -e "  ${BOLD}Следующие шаги:${NC}"
echo -e "    1. Перелогиньтесь в систему или выполните:"
echo -e "       ${CYAN}source /etc/profile.d/agent_env.sh${NC}"
echo -e "    2. Соберите проект:"
echo -e "       ${CYAN}cd /path/to/project && cargo build --release${NC}"
echo -e "    3. Запустите агент:"
echo -e "       ${CYAN}./target/release/agent${NC}"
echo ""
echo -e "${BOLD}${BLUE}======================================================================${NC}"
