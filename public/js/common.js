/**
 * Secure User Authentication System - Client-Side Common Utilities
 * Enforces secure credentials handling, CSRF token management, and session state.
 */

window.AuthApp = (function () {
  let cachedCsrfToken = null;

  /**
   * Fetches the session-bound CSRF token from the backend.
   */
  async function getCsrfToken() {
    if (cachedCsrfToken) {
      return cachedCsrfToken;
    }
    try {
      const res = await fetch('/api/csrf-token', {
        credentials: 'include',
      });
      if (res.ok) {
        const data = await res.json();
        cachedCsrfToken = data.csrfToken;
        return cachedCsrfToken;
      }
    } catch (err) {
      console.warn('[Security] Could not retrieve CSRF token:', err);
    }
    return '';
  }

  /**
   * Stores the session token in tab sessionStorage for cross-origin iframe resilience.
   */
  function setSessionId(id) {
    if (id) {
      sessionStorage.setItem('auth_session_id', id);
    } else {
      sessionStorage.removeItem('auth_session_id');
    }
  }

  function getSessionId() {
    return sessionStorage.getItem('auth_session_id') || '';
  }

  /**
   * Wraps fetch() with safe defaults:
   * - includes credentials (cookies)
   * - automatically injects X-CSRF-Token on state-changing requests
   * - attaches X-Session-ID header fallback for cross-origin iframes
   * - parses JSON safely
   */
  async function apiFetch(url, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    };

    // Attach CSRF token on mutating requests
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
      const csrf = await getCsrfToken();
      if (csrf) {
        headers['X-CSRF-Token'] = csrf;
      }
    }

    // Attach session token fallback if available (assists browsers blocking 3rd-party cookies in iframes)
    const sessionId = getSessionId();
    if (sessionId) {
      headers['X-Session-ID'] = sessionId;
    }

    try {
      const res = await fetch(url, {
        ...options,
        headers,
        credentials: 'include',
      });

      let data;
      try {
        data = await res.json();
      } catch {
        data = { success: res.ok, error: `Server returned HTTP ${res.status}` };
      }

      return {
        status: res.status,
        ok: res.ok,
        data,
      };
    } catch (networkErr) {
      // Automatic quick retry for idempotent GET requests to tolerate server boot latency
      if (method === 'GET' && !options._isRetry) {
        await new Promise((resolve) => setTimeout(resolve, 800));
        return apiFetch(url, { ...options, _isRetry: true });
      }
      return {
        status: 0,
        ok: false,
        data: {
          success: false,
          error: (networkErr && networkErr.message) || 'Network connection unavailable',
        },
      };
    }
  }

  /**
   * Checks current server session status and syncs top navigation.
   */
  async function checkAuthStatus() {
    try {
      const { ok, data } = await apiFetch('/api/auth/status');
      const navAuthSlot = document.getElementById('nav-auth-slot');
      if (!navAuthSlot) return data;

      if (ok && data.authenticated && data.user) {
        navAuthSlot.innerHTML = `
          <a href="/dashboard.html" class="btn btn-secondary">Dashboard (${escapeHtml(data.user.name.split(' ')[0])})</a>
          <button id="nav-logout-btn" class="btn btn-danger">Log Out</button>
        `;
        const logoutBtn = document.getElementById('nav-logout-btn');
        if (logoutBtn) {
          logoutBtn.addEventListener('click', async () => {
            await handleLogout();
          });
        }
      } else {
        navAuthSlot.innerHTML = `
          <a href="/login.html" class="btn btn-secondary">Log In</a>
          <a href="/register.html" class="btn btn-primary">Register</a>
        `;
      }
      return data;
    } catch (err) {
      console.error('[Auth] Failed to check status:', err);
      return { authenticated: false };
    }
  }

  /**
   * Performs secure logout flow:
   * Destroys server-side session, clears client state, redirects to login.
   */
  async function handleLogout() {
    try {
      const { ok, data } = await apiFetch('/api/logout', { method: 'POST' });
      cachedCsrfToken = null;
      setSessionId(null);
      window.location.href = '/login.html?logged_out=true';
    } catch (err) {
      console.error('Logout error:', err);
      setSessionId(null);
      window.location.href = '/login.html';
    }
  }

  /**
   * Sanitizes string to prevent XSS in dynamic DOM inserts.
   */
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Setup show/hide password buttons
  function initPasswordToggles() {
    document.querySelectorAll('[data-password-toggle]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-password-toggle');
        const input = document.getElementById(targetId);
        if (!input) return;
        if (input.type === 'password') {
          input.type = 'text';
          btn.setAttribute('aria-label', 'Hide password');
          btn.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
              <line x1="1" y1="1" x2="23" y2="23"></line>
            </svg>
          `;
        } else {
          input.type = 'password';
          btn.setAttribute('aria-label', 'Show password');
          btn.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
          `;
        }
      });
    });
  }

  // Automatically sync auth status and password toggles on load
  document.addEventListener('DOMContentLoaded', () => {
    checkAuthStatus();
    initPasswordToggles();
  });

  return {
    apiFetch,
    getCsrfToken,
    checkAuthStatus,
    handleLogout,
    escapeHtml,
    initPasswordToggles,
    setSessionId,
    getSessionId,
  };
})();
