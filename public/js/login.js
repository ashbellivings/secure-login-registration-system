/**
 * Login Controller
 * Handles user authentication with credential validation and session redirection.
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('login-form');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const submitBtn = document.getElementById('submit-btn');
  const alertBox = document.getElementById('alert-box');
  const alertMessage = document.getElementById('alert-message');

  // Check URL query parameters
  const urlParams = new URLSearchParams(window.location.search);
  const registeredEmail = urlParams.get('registered_email');
  const loggedOut = urlParams.get('logged_out');
  const sessionExpired = urlParams.get('expired');

  if (registeredEmail) {
    emailInput.value = decodeURIComponent(registeredEmail);
    showAlert('Account created successfully! Please enter your password to log in.', 'success');
    passwordInput.focus();
  } else if (loggedOut) {
    showAlert('You have been securely logged out. Session destroyed.', 'info');
  } else if (sessionExpired) {
    showAlert('Your session has expired or is invalid. Please log in again.', 'error');
  } else {
    if (!emailInput.value) {
      emailInput.value = 'alexmorgan@gmail.com';
      passwordInput.value = 'alexmorgan1';
    }
  }

  function showAlert(msg, type = 'error') {
    alertBox.className = `alert alert-${type}`;
    alertMessage.textContent = msg;
    alertBox.classList.remove('hidden');
  }

  function hideAlert() {
    alertBox.classList.add('hidden');
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const email = emailInput.value.trim();
    const password = passwordInput.value;

    if (!email || !password) {
      showAlert('Please enter both your email address and password.');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Authenticating...';

    try {
      const response = await window.AuthApp.apiFetch('/api/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });

      if (response.ok && response.data.success) {
        if (response.data.sessionId) {
          window.AuthApp.setSessionId(response.data.sessionId);
        }
        showAlert('Authentication verified. Redirecting to dashboard...', 'success');
        setTimeout(() => {
          window.location.href = '/dashboard.html';
        }, 300);
      } else {
        // Enforce generic message to prevent account enumeration
        const errorText = response.status === 429
          ? 'Rate limit exceeded: Too many login attempts. Please wait 15 minutes.'
          : (response.data.error || 'Invalid email or password.');
        showAlert(errorText, 'error');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Log In';
      }
    } catch (err) {
      showAlert('Network error: Unable to connect to the authentication server.', 'error');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Log In';
    }
  });

  // Demo account autofill buttons
  const fillAdminBtn = document.getElementById('btn-fill-admin');
  const fillAlexBtn = document.getElementById('btn-fill-alex');
  const fillAnalystBtn = document.getElementById('btn-fill-analyst');

  if (fillAdminBtn) {
    fillAdminBtn.addEventListener('click', () => {
      emailInput.value = 'lijinlivi@gmail.com';
      passwordInput.value = 'lijinlivi@2006';
      hideAlert();
    });
  }

  if (fillAlexBtn) {
    fillAlexBtn.addEventListener('click', () => {
      emailInput.value = 'alexmorgan@gmail.com';
      passwordInput.value = 'alexmorgan1';
      hideAlert();
    });
  }

  if (fillAnalystBtn) {
    fillAnalystBtn.addEventListener('click', () => {
      emailInput.value = 'intern@cyberlab.org';
      passwordInput.value = 'InternPassword123!';
      hideAlert();
    });
  }
});
