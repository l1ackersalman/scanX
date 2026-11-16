#!/usr/bin/env bash
# =====================================================================
# scanX Start Script
# Starts the Django development server and background worker.
# =====================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# ---------------------------------------------------------------------
# Load environment
# ---------------------------------------------------------------------
if [[ -f ".env" ]]; then
    # shellcheck disable=SC1091
    source .env
    log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
    log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
    log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
    log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
else
    log_error ".env file not found. Run ./scripts/install.sh first."
    exit 1
fi

# ---------------------------------------------------------------------
# Activate virtual environment
# ---------------------------------------------------------------------
if [[ -d "venv" ]]; then
    source venv/bin/activate
else
    log_error "Virtual environment not found. Run ./scripts/install.sh first."
    exit 1
fi

# ---------------------------------------------------------------------
# Check required tools
# ---------------------------------------------------------------------
log_info "Checking required tools..."
python manage.py check_tools || {
    log_warn "Some tools are missing. Scans may fail."
}

# ---------------------------------------------------------------------
# Start services
# ---------------------------------------------------------------------
log_info "Starting scanX services..."

# Function to cleanup on exit
cleanup() {
    log_info "Shutting down..."
    if [[ -n "${WORKER_PID:-}" ]]; then
        kill "$WORKER_PID" 2>/dev/null || true
    fi
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi
    exit 0
}
trap cleanup INT TERM

# Start background worker
log_info "Starting background worker..."
python manage.py worker &
WORKER_PID=$!
log_success "Worker started (PID: $WORKER_PID)"

# Start Django development server
HOST="${DJANGO_HOST:-0.0.0.0}"
PORT="${DJANGO_PORT:-8000}"
log_info "Starting Django server on $HOST:$PORT..."
python manage.py runserver "$HOST:$PORT" &
SERVER_PID=$!
log_success "Django server started (PID: $SERVER_PID)"

echo ""
echo -e "${GREEN}=============================================================${NC}"
echo -e "${GREEN}  scanX is running!${NC}"
echo -e "${GREEN}=============================================================${NC}"
echo ""
echo "  Web UI:     http://localhost:8000"
echo "  Admin:      http://localhost:8000/admin/"
echo "  Worker PID: $WORKER_PID"
echo "  Server PID: $SERVER_PID"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Wait for both processes
wait $WORKER_PID $SERVER_PID