/**
 * scanX JavaScript — Live log streaming, theme toggle, UI interactions
 */

(function() {
  'use strict';

  // =====================================================================
  // Theme Toggle
  // =====================================================================
  const themeToggle = document.getElementById('themeToggle');
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

  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const isLight = document.documentElement.getAttribute('data-theme') === 'light';
      applyTheme(isLight ? 'dark' : 'light');
    });
    initTheme();
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
        const url = `/scanner/scan/${this.scanId}/logs/?since=${this.offset}`;
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
          // Refresh page after a short delay to show final state
          setTimeout(() => window.location.reload(), 2000);
        } else {
          this.timer = setTimeout(() => this.poll(), this.pollInterval);
        }
      } catch (error) {
        console.error('Log stream error:', error);
        this.timer = setTimeout(() => this.poll(), this.pollInterval * 2);
      }
    }

    appendLogs(lines) {
      if (!lines.length) return;

      const fragment = document.createDocumentFragment();
      lines.forEach(line => {
        const div = document.createElement('div');
        div.className = 'log-line';
        div.innerHTML = this.formatLogLine(line);
        fragment.appendChild(div);
      });

      this.logContainer.appendChild(fragment);
      this.scrollToBottom();
    }

    formatLogLine(line) {
      // Escape HTML
      const escaped = line
        .replace(/&/g, '&')
        .replace(/</g, '<')
        .replace(/>/g, '>');

      // Detect log patterns and add classes
      let cssClass = 'log-info';
      if (escaped.includes('[✔]') || escaped.includes('[+]') || escaped.includes('SUCCESS')) {
        cssClass = 'log-success';
      } else if (escaped.includes('[!]') || escaped.includes('[✘]') || escaped.includes('FAILED') || escaped.includes('ERROR')) {
        cssClass = 'log-error';
      } else if (escaped.includes('⏱') || escaped.includes('Total Execution')) {
        cssClass = 'log-progress';
      } else if (escaped.includes('found') || escaped.includes('domains') || escaped.includes('Scanning')) {
        cssClass = 'log-progress';
      }

      // Extract timestamp if present (optional)
      return `<span class="${cssClass}">${escaped}</span>`;
    }

    scrollToBottom() {
      this.logContainer.scrollTop = this.logContainer.scrollHeight;
    }

    updateStatus(status) {
      if (!this.statusContainer) return;

      const statusMap = {
        'pending': { label: 'Pending', class: 'status-pending' },
        'running': { label: 'Running', class: 'status-running' },
        'completed': { label: 'Completed', class: 'status-completed' },
        'failed': { label: 'Failed', class: 'status-failed' },
      };

      const info = statusMap[status] || { label: status, class: '' };
      this.statusContainer.innerHTML = `
        <span class="status-badge ${info.class}">${info.label}</span>
      `;
    }
  }

  // =====================================================================
  // Initialize LogStream on scan detail page
  // =====================================================================
  function initLogStream() {
    const logContainer = document.getElementById('log-viewer');
    const statusContainer = document.getElementById('scan-status-badge');

    if (!logContainer || !statusContainer) return;

    const scanId = logContainer.dataset.scanId;
    if (!scanId) return;

    const initialOffset = parseInt(logContainer.dataset.initialOffset || '0', 10);
    const initialStatus = logContainer.dataset.initialStatus || 'pending';

    // Set initial status
    const statusMap = {
      'pending': { label: 'Pending', class: 'status-pending' },
      'running': { label: 'Running', class: 'status-running' },
      'completed': { label: 'Completed', class: 'status-completed' },
      'failed': { label: 'Failed', class: 'status-failed' },
    };
    const info = statusMap[initialStatus] || { label: initialStatus, class: '' };
    statusContainer.innerHTML = `<span class="status-badge ${info.class}">${info.label}</span>`;

    // Start streaming if not terminal
    if (initialStatus === 'pending' || initialStatus === 'running') {
      const stream = new LogStream(scanId, logContainer, statusContainer, {
        initialOffset: initialOffset,
        pollInterval: 1500,
        onComplete: (finalStatus) => {
          console.log('Scan completed with status:', finalStatus);
        },
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
    initTheme();
    initLogStream();
    initForms();
    initCopyButtons();
    initKeyboardShortcuts();
  });

  // Expose for external use
  window.scanX = { LogStream };

})();