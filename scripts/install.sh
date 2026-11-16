#!/usr/bin/env bash
# =====================================================================
# scanX Installation Script
# Installs dependencies, sets up environment, and prepares the application.
# =====================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "${BLUE}=============================================================${NC}"
echo -e "${BLUE}  scanX Installation Script${NC}"
echo -e "${BLUE}=============================================================${NC}"
echo ""

# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------
# Check system requirements
# ---------------------------------------------------------------------
log_info "Checking system requirements..."

# Python 3.10+
if command_exists python3; then
    PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    log_success "Python $PY_VERSION found"
else
    log_error "Python 3.10+ is required but not found"
    exit 1
fi

# Git
if command_exists git; then
    log_success "Git found"
else
    log_warn "Git not found (recommended for version control)"
fi

# Go (for tools)
if command_exists go; then
    GO_VERSION=$(go version | awk '{print $3}')
    log_success "Go $GO_VERSION found"
    GOPATH=$(go env GOPATH)
    GOBIN="$GOPATH/bin"
    log_info "GOPATH: $GOPATH"
    log_info "GOBIN: $GOBIN"
else
    log_warn "Go not found - external tools (subfinder, httpx, etc.) must be installed manually"
fi

# ---------------------------------------------------------------------
# Create virtual environment
# ---------------------------------------------------------------------
log_info "Setting up Python virtual environment..."

if [[ ! -d "venv" ]]; then
    python3 -m venv venv
    log_success "Virtual environment created"
else
    log_info "Virtual environment already exists"
fi

# Activate venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip >/dev/null 2>&1

# Install Python dependencies
log_info "Installing Python dependencies..."
pip install -r requirements.txt
log_success "Python dependencies installed"

# ---------------------------------------------------------------------
# Install Go tools (optional but recommended)
# ---------------------------------------------------------------------
if command_exists go; then
    log_info "Installing Go-based reconnaissance tools..."
    echo "This may take a few minutes..."

    TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/crt/cmd/crt@latest"
    )

    for tool in "${TOOLS[@]}"; do
        tool_name=$(basename "$tool" | cut -d'@' -f1)
        if ! command_exists "$tool_name"; then
            log_info "Installing $tool_name..."
            go install -v "$tool" >/dev/null 2>&1 || log_warn "Failed to install $tool_name"
        else
            log_info "$tool_name already installed"
        fi
    done

    # Verify installations
    for tool in subfinder assetfinder chaos dnsx httpx crt; do
        if command_exists "$tool"; then
            log_success "$tool installed"
        else
            log_warn "$tool not found in PATH (may need to add \$GOPATH/bin to PATH)"
        fi
    done
fi

# ---------------------------------------------------------------------
# Install figlet
# ---------------------------------------------------------------------
if ! command_exists figlet; then
    log_info "Installing figlet..."
    if command_exists apt-get; then
        sudo apt-get update && sudo apt-get install -y figlet
    elif command_exists brew; then
        brew install figlet
    elif command_exists dnf; then
        sudo dnf install -y figlet
    elif command_exists pacman; then
        sudo pacman -S --noconfirm figlet
    else
        log_warn "Could not install figlet automatically. Please install manually."
    fi
else
    log_success "figlet already installed"
fi

# ---------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------
log_info "Setting up environment configuration..."

if [[ ! -f ".env" ]]; then
    cp .env.example .env
    log_success "Created .env from .env.example"
    log_warn "Please edit .env and set your CHAOS_API_KEY and other settings"
else
    log_info ".env already exists"
fi

# ---------------------------------------------------------------------
# Create data directory
# ---------------------------------------------------------------------
log_info "Creating scan data directory..."
mkdir -p scan_data
log_success "scan_data directory ready"

# ---------------------------------------------------------------------
# Run Django migrations
# ---------------------------------------------------------------------
log_info "Running Django migrations..."
python manage.py migrate
log_success "Database migrated"

# ---------------------------------------------------------------------
# Collect static files
# ---------------------------------------------------------------------
log_info "Collecting static files..."
python manage.py collectstatic --noinput
log_success "Static files collected"

# ---------------------------------------------------------------------
# Verify scanner script
# ---------------------------------------------------------------------
if [[ -f "scanner/scanx.sh" ]]; then
    chmod +x scanner/scanx.sh
    log_success "Scanner script is executable"
else
    log_error "Scanner script not found at scanner/scanx.sh"
    exit 1
fi

# ---------------------------------------------------------------------
# Run tool check
# ---------------------------------------------------------------------
log_info "Verifying external tools..."
python manage.py check_tools --install-hints || true

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------
echo ""
echo -e "${GREEN}=============================================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}=============================================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Edit .env and add your CHAOS_API_KEY"
echo "  2. Start the development server:"
echo "     ./scripts/start.sh"
echo "  3. Or run components manually:"
echo "     source venv/bin/activate"
echo "     python manage.py runserver 0.0.0.0:8000"
echo "     # In another terminal:"
echo "     python manage.py worker"
echo ""
echo "Access the web UI at: http://localhost:8000"
echo ""