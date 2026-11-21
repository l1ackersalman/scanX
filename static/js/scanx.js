/**
 * scanX JavaScript — Live log streaming, theme toggle, UI interactions
 */

(function() {
  'use strict';

  // =====================================================================
  // Theme Toggle (shared)
  // =====================================================================
  const THEME_KEY = 'sx-theme';

  function applyTheme(theme) {
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    localStorage.setItem(THEME_KEY, theme);
  }

  function initTheme() {
    const saved = localStorage.getItem(THEME_KEY);
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const initial = saved || (prefersDark ? 'dark' : 'light');
    applyTheme(initial);
  }

  function setupThemeToggle(toggle) {
    if (!toggle) return;
    toggle.addEventListener('click', () => {
      const isLight = document.documentElement.getAttribute('data-theme') === 'light';
      applyTheme(isLight ? 'dark' : 'light');
    });
  }

  // Initialize theme and setup all toggles
  initTheme();
  setupThemeToggle(document.getElementById('themeToggle'));
  setupThemeToggle(document.getElementById('themeToggleSidebar'));
  setupThemeToggle(document.getElementById('themeToggleMobile'));

  // =====================================================================
  // Mobile Sidebar Toggle
  // =====================================================================
  function initMobileSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    const menuBtn = document.getElementById('mobileMenuBtn');

    if (!sidebar || !overlay || !menuBtn) return;

    function openSidebar() {
      sidebar.classList.add('open');
      overlay.classList.add('visible');
      menuBtn.setAttribute('aria-expanded', 'true');
      document.body.style.overflow = 'hidden';
    }

    function closeSidebar() {
      sidebar.classList.remove('open');
      overlay.classList.remove('visible');
      menuBtn.setAttribute('aria-expanded', 'false');
      document.body.style.overflow = '';
    }

    function toggleSidebar() {
      if (sidebar.classList.contains('open')) {
        closeSidebar();
      } else {
        openSidebar();
      }
    }

    menuBtn.addEventListener('click', toggleSidebar);
    overlay.addEventListener('click', closeSidebar);

    // Close on escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && sidebar.classList.contains('open')) {
        closeSidebar();
      }
    });
  }

  // =====================================================================
  // LogStream — Polls for live scan logs
  // =====================================================================
  class LogStream {
    constructor(scanId, logContainer, statusContainer, options = {}) {
      this.scanId = scanId;
      this.logContainer = logContainer;
      this.statusContainer = statusContainer;
      this.offset = options.initialOffset || 0;
      this.pollInterval = options.pollInterval || 1500;
      this.timer = null;
      this.isRunning = false;
      this.onComplete = options.onComplete || null;
      this.refreshCountdown = options.refreshCountdown || 3; // seconds
    }

    start() {
      if (this.isRunning) return;
      this.isRunning = true;
      this.poll();
    }

    stop() {
      this.isRunning = false;
      if (this.timer) {
        clearTimeout(this.timer);
        this.timer = null;
      }
    }

    async poll() {
      if (!this.isRunning) return;

      try {
        const url = `/scan/${this.scanId}/logs/?since=${this.offset}`;
        const response = await fetch(url, {
          headers: { 'Accept': 'application/json' },
          credentials: 'same-origin',
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        this.offset = data.offset;
        this.appendLogs(data.lines);
        this.updateStatus(data.status);

        if (data.is_terminal) {
          this.stop();
          if (this.onComplete) this.onComplete(data.status);
          this.showRefreshCountdown(data.status);
        } else {
          this.timer = setTimeout(() => this.poll(), this.pollInterval);
        }
      } catch (error) {
        console.error('Log stream error:', error);
        this.timer = setTimeout(() => this.poll(), this.pollInterval * 2);
      }
    }

    showRefreshCountdown(status) {
      const logContainer = this.logContainer;

      // Remove any existing countdown banner
      const existing = logContainer.querySelector('.refresh-banner');
      if (existing) existing.remove();

      // Create countdown banner
      const banner = document.createElement('div');
      banner.className = 'refresh-banner';
      banner.style.cssText = `
        padding: var(--sx-space-3);
        background: var(--sx-surface-hover);
        border-top: 1px solid var(--sx-border);
        font-family: var(--sx-font-mono);
        font-size: var(--sx-text-xs);
        color: var(--sx-text-secondary);
        text-align: center;
      `;

      let remaining = this.refreshCountdown;
      banner.textContent = `Scan ${status}. Refreshing in ${remaining}s...`;
      logContainer.appendChild(banner);
      logContainer.scrollTop = logContainer.scrollHeight;

      const interval = setInterval(() => {
        remaining--;
        banner.textContent = `Scan ${status}. Refreshing in ${remaining}s...`;
        logContainer.scrollTop = logContainer.scrollHeight;

        if (remaining <= 0) {
          clearInterval(interval);
          window.location.reload();
        }
      }, 1000);
    }

    appendLogs(lines) {
      if (!lines.length) return;

      const fragment = document.createDocumentFragment();
      lines.forEach(line => {
        const div = document.createElement('div');
        div.className = 'log-line';
        div.innerHTML = this.formatLogLine(line);  // formatLogLine escapes the text
        fragment.appendChild(div);
      });

      // Lines go inside the <pre> so they keep its padding and wrapping
      (this.logContainer.querySelector('pre') || this.logContainer).appendChild(fragment);
      this.scrollToBottom();
    }

    formatLogLine(line) {
      // Escape HTML properly
      const escaped = line
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');

      // Detect log patterns and add classes
      let cssClass = 'log-info';
      const lower = escaped.toLowerCase();

      // Tool-specific results (checked first before generic patterns)
      if (lower.includes('subfinder')) {
        cssClass = 'log-subfinder';
      }
      else if (lower.includes('assetfinder')) {
        cssClass = 'log-assetfinder';
      }
      else if (lower.includes('chaos')) {
        cssClass = 'log-chaos';
      }
      else if (lower.includes('crt.sh') || lower.includes('crt ')) {
        cssClass = 'log-crt';
      }
      // Status icons
      else if (escaped.includes('[✔]')) {
        cssClass = 'log-success';
      }
      else if (escaped.includes('[✘]') || escaped.includes('[!]')) {
        cssClass = 'log-error';
      }
      // Live / unique domain counts
      else if (lower.includes('live domains') || lower.includes('live.txt')) {
        cssClass = 'log-live';
      }
      else if (lower.includes('unique domains') || lower.includes('alldomains')) {
        cssClass = 'log-success';
      }
      // HTTP results
      else if (lower.includes('success')) {
        cssClass = 'log-live';
      }
      else if (lower.includes('failed')) {
        cssClass = 'log-error';
      }
      // Execution time
      else if (lower.includes('total execution') || lower.includes('⏱')) {
        cssClass = 'log-time';
      }
      // Generic errors
      else if (escaped.includes('ERROR') || escaped.includes('error')) {
        cssClass = 'log-error';
      }
      // Progress indicators ([+], found, domains, scanning) - catch-all last
      else if (escaped.includes('[+]') || lower.includes('found') || lower.includes('domains') || lower.includes('scanning')) {
        cssClass = 'log-progress';
      }

      return `<span class="${cssClass}">${escaped}</span>`;
    }

    scrollToBottom() {
      this.logContainer.scrollTop = this.logContainer.scrollHeight;
    }

    updateStatus(status) {
      if (!this.statusContainer) return;
      renderStatusBadge(this.statusContainer, status);
    }
  }

  const STATUS_LABELS = {
    pending: 'Pending', running: 'Running', completed: 'Completed',
    failed: 'Failed', cancelled: 'Cancelled',
  };

  function renderStatusBadge(container, status) {
    const badge = document.createElement('span');
    badge.className = 'status-badge' + (STATUS_LABELS[status] ? ` status-${status}` : '');
    badge.textContent = STATUS_LABELS[status] || String(status);
    container.replaceChildren(badge);
  }

  // =====================================================================
  // Initialize LogStream on scan detail page
  // =====================================================================
  function initLogStream() {
    const logContainer = document.getElementById('log-viewer');
    const statusContainer = document.getElementById('scan-status-badge');

    if (!logContainer) return;

    const scanId = logContainer.dataset.scanId;
    if (!scanId) return;

    const initialOffset = parseInt(logContainer.dataset.initialOffset || '0', 10);
    const initialStatus = logContainer.dataset.initialStatus || 'pending';

    // Start streaming if not terminal (the countdown banner reloads the page when done)
    if (initialStatus === 'pending' || initialStatus === 'running') {
      const stream = new LogStream(scanId, logContainer, statusContainer || null, {
        initialOffset: initialOffset,
        pollInterval: 1500,
      });
      stream.start();

      // Expose for debugging
      window.scanXLogStream = stream;
    }
  }

  // =====================================================================
  // Form Enhancements
  // =====================================================================
  function initForms() {
    // Domain input: lowercase on blur
    const domainInput = document.getElementById('id_domain');
    if (domainInput) {
      domainInput.addEventListener('blur', () => {
        domainInput.value = domainInput.value.trim().toLowerCase();
      });
    }

    // Authorization checkbox: enable/disable submit
    const authCheckbox = document.getElementById('id_authorized');
    const authByInput = document.getElementById('id_authorized_by');
    const submitBtn = document.querySelector('form button[type="submit"]');

    if (authCheckbox && authByInput && submitBtn) {
      function updateSubmit() {
        submitBtn.disabled = !(authCheckbox.checked && authByInput.value.trim());
      }
      authCheckbox.addEventListener('change', updateSubmit);
      authByInput.addEventListener('input', updateSubmit);
      updateSubmit();
    }
  }

  // =====================================================================
  // Copy to Clipboard
  // =====================================================================
  function initCopyButtons() {
    document.querySelectorAll('[data-copy]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const targetId = btn.dataset.copy;
        const target = document.getElementById(targetId);
        if (!target) return;

        const text = target.textContent || target.value || '';
        try {
          await navigator.clipboard.writeText(text);
          const original = btn.textContent;
          btn.textContent = 'Copied!';
          setTimeout(() => { btn.textContent = original; }, 2000);
        } catch (e) {
          console.error('Copy failed:', e);
        }
      });
    });
  }

  // =====================================================================
  // Keyboard Shortcuts
  // =====================================================================
  function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      // Ctrl/Cmd + K: Focus search (future)
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = document.querySelector('input[type="search"]');
        if (searchInput) searchInput.focus();
      }
    });
  }

  // =====================================================================
  // Initialize on DOM Ready
  // =====================================================================
  document.addEventListener('DOMContentLoaded', () => {
    initMobileSidebar();
    initLogStream();
    initForms();
    initCopyButtons();
    initKeyboardShortcuts();
  });

  // Expose for external use
  window.scanX = { LogStream };

})();