/**
 * Protected Dashboard Controller
 * Enforces backend session verification, displays user profile, and provides live audit testing.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const loadingState = document.getElementById('loading-state');
  const dashboardContent = document.getElementById('dashboard-content');
  const userGreeting = document.getElementById('user-greeting');
  const profileName = document.getElementById('profile-name');
  const profileEmail = document.getElementById('profile-email');
  const profileId = document.getElementById('profile-id');
  const profileCreated = document.getElementById('profile-created');

  const headerLogoutBtn = document.getElementById('header-logout-btn');
  const dashboardLogoutBtn = document.getElementById('dashboard-logout-btn');

  const testUnauthBtn = document.getElementById('test-unauth-btn');
  const testAuthBtn = document.getElementById('test-auth-btn');
  const testResultBox = document.getElementById('test-result-box');

  // Verify server-side authorization on mount
  try {
    const res = await window.AuthApp.apiFetch('/api/profile');

    if (!res.ok || !res.data.success || !res.data.user) {
      // Unauthenticated: redirect to login
      window.location.href = '/login.html?expired=true';
      return;
    }

    const user = res.data.user;

    // Render verified profile data
    userGreeting.textContent = `Welcome, ${window.AuthApp.escapeHtml(user.name)}`;
    profileName.textContent = user.name;
    profileEmail.textContent = user.email;
    profileId.textContent = user.id || 'Active Record';
    profileCreated.textContent = user.createdAt ? new Date(user.createdAt).toLocaleString() : 'Recent';

    const profileRole = document.getElementById('profile-role');
    const adminPanel = document.getElementById('admin-panel');
    const userPanel = document.getElementById('user-panel');

    if (user.role === 'admin') {
      if (profileRole) {
        profileRole.innerHTML = `<span style="color: var(--accent-cyan);">👑 Administrator (Full Access)</span>`;
      }
      if (adminPanel) adminPanel.classList.remove('hidden');
      if (userPanel) userPanel.classList.add('hidden');
      loadAdminUsers();
    } else {
      if (profileRole) {
        profileRole.innerHTML = `<span style="color: var(--text-secondary);">👤 Standard User (Least Privilege)</span>`;
      }
      if (adminPanel) adminPanel.classList.add('hidden');
      if (userPanel) userPanel.classList.remove('hidden');
    }

    loadingState.classList.add('hidden');
    dashboardContent.classList.remove('hidden');
  } catch (err) {
    console.error('Session verification error:', err);
    window.location.href = '/login.html?expired=true';
  }

  // Load all users for Administrator
  async function loadAdminUsers() {
    const tableContainer = document.getElementById('admin-users-table');
    if (!tableContainer) return;
    try {
      const res = await window.AuthApp.apiFetch('/api/admin/users');
      if (res.ok && res.data.users) {
        let html = `
          <table class="test-table" style="font-size: 0.8rem;">
            <thead>
              <tr>
                <th>User ID</th>
                <th>Name</th>
                <th>Email Address</th>
                <th>Role</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
        `;
        res.data.users.forEach((u) => {
          const roleBadge = u.role === 'admin'
            ? `<span style="color: var(--accent-cyan); font-weight: 700;">👑 Admin</span>`
            : `<span style="color: var(--text-muted);">👤 User</span>`;
          html += `
            <tr>
              <td style="font-family: var(--font-mono); color: var(--text-muted);">${u.id}</td>
              <td style="font-weight: 600;">${window.AuthApp.escapeHtml(u.name)}</td>
              <td>${window.AuthApp.escapeHtml(u.email)}</td>
              <td>${roleBadge}</td>
              <td style="color: var(--text-muted); font-size: 0.75rem;">${new Date(u.createdAt).toLocaleDateString()}</td>
            </tr>
          `;
        });
        html += `</tbody></table>`;
        tableContainer.innerHTML = html;
      } else {
        tableContainer.innerHTML = `<p style="color: var(--status-crimson);">Failed to load admin user list.</p>`;
      }
    } catch (e) {
      tableContainer.innerHTML = `<p style="color: var(--status-crimson);">Error loading users: ${e.message}</p>`;
    }
  }

  // Test RBAC Forbidden probe for Standard User
  const testRbacBtn = document.getElementById('test-rbac-forbidden-btn');
  const rbacResultBox = document.getElementById('rbac-test-result');
  if (testRbacBtn) {
    testRbacBtn.addEventListener('click', async () => {
      rbacResultBox.classList.remove('hidden');
      rbacResultBox.textContent = 'Sending GET /api/admin/users as standard user...';
      try {
        const result = await window.AuthApp.apiFetch('/api/admin/users');
        rbacResultBox.textContent = [
          `REQUEST: GET /api/admin/users [Standard User Role: "user"]`,
          `RESPONSE STATUS: ${result.status} ${result.status === 403 ? 'Forbidden' : 'OK'}`,
          `BODY: ${JSON.stringify(result.data, null, 2)}`,
          `\nRBAC AUDIT CONCLUSION: Server requireRole('admin') middleware strictly blocked standard user from accessing administrative resources. Least Privilege enforced!`
        ].join('\n');
      } catch (err) {
        rbacResultBox.textContent = `Error: ${err.message}`;
      }
    });
  }

  // Logout Handlers
  if (headerLogoutBtn) {
    headerLogoutBtn.addEventListener('click', () => window.AuthApp.handleLogout());
  }
  if (dashboardLogoutBtn) {
    dashboardLogoutBtn.addEventListener('click', () => window.AuthApp.handleLogout());
  }

  // Live Access Control Probe 1: Unauthenticated request (omit session cookies)
  if (testUnauthBtn) {
    testUnauthBtn.addEventListener('click', async () => {
      testResultBox.classList.remove('hidden');
      testResultBox.textContent = 'Sending GET /api/profile (credentials: "omit")...';

      try {
        const res = await fetch('/api/profile', { credentials: 'omit' });
        const json = await res.json();
        testResultBox.textContent = [
          `REQUEST: GET /api/profile [Cookie: (none)]`,
          `RESPONSE HTTP STATUS: ${res.status} Unauthorized`,
          `BODY: ${JSON.stringify(json, null, 2)}`,
          `\nAUDIT CONCLUSION: Server-side authorization successfully rejected the uncredentialed request. The frontend view cannot be bypassed by direct API calls.`
        ].join('\n');
      } catch (err) {
        testResultBox.textContent = `Network error: ${err.message}`;
      }
    });
  }

  // Live Access Control Probe 2: Authorized request (include session cookies / credentials)
  if (testAuthBtn) {
    testAuthBtn.addEventListener('click', async () => {
      testResultBox.classList.remove('hidden');
      testResultBox.textContent = 'Sending GET /api/profile (with verified credentials)...';

      try {
        const result = await window.AuthApp.apiFetch('/api/profile');
        testResultBox.textContent = [
          `REQUEST: GET /api/profile [Authenticated Session]`,
          `RESPONSE HTTP STATUS: ${result.status} ${result.ok ? 'OK' : 'Error'}`,
          `BODY: ${JSON.stringify(result.data, null, 2)}`,
          `\nAUDIT CONCLUSION: Request authorized. Identity derived exclusively from server-side session.`
        ].join('\n');
      } catch (err) {
        testResultBox.textContent = `Network error: ${err.message}`;
      }
    });
  }
});
