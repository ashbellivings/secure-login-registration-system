/**
 * Registration Controller
 * Handles client-side password policy validation and secure submission to /api/register.
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('register-form');
  const nameInput = document.getElementById('name');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const submitBtn = document.getElementById('submit-btn');
  const alertBox = document.getElementById('alert-box');
  const alertMessage = document.getElementById('alert-message');

  const reqLength = document.getElementById('req-length');
  const reqLetter = document.getElementById('req-letter');
  const reqNumber = document.getElementById('req-number');

  // Real-time password requirement updates
  passwordInput.addEventListener('input', () => {
    const val = passwordInput.value;
    
    // Check length >= 8 and <= 72
    const hasLength = val.length >= 8 && val.length <= 72;
    toggleReq(reqLength, hasLength);

    // Check letter
    const hasLetter = /[a-zA-Z]/.test(val);
    toggleReq(reqLetter, hasLetter);

    // Check number or symbol
    const hasNumber = /[0-9!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(val);
    toggleReq(reqNumber, hasNumber);
  });

  function toggleReq(element, isMet) {
    if (!element) return;
    if (isMet) {
      element.classList.add('met');
      element.querySelector('.req-icon').textContent = '✓';
    } else {
      element.classList.remove('met');
      element.querySelector('.req-icon').textContent = '●';
    }
  }

  function showAlert(msg, type = 'error') {
    alertBox.className = `alert alert-${type}`;
    alertMessage.textContent = msg;
    alertBox.classList.remove('hidden');
    alertBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function hideAlert() {
    alertBox.classList.add('hidden');
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const name = nameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;

    // Frontend validation
    if (!name || name.length < 2 || name.length > 50) {
      showAlert('Full name must be between 2 and 50 characters.');
      nameInput.focus();
      return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
      showAlert('Please enter a valid email address.');
      emailInput.focus();
      return;
    }

    if (!password || password.length < 8) {
      showAlert('Password must be at least 8 characters long.');
      passwordInput.focus();
      return;
    }

    if (password.length > 72) {
      showAlert('Password must not exceed 72 characters.');
      passwordInput.focus();
      return;
    }

    // Submit to backend
    submitBtn.disabled = true;
    submitBtn.textContent = 'Registering Account...';

    try {
      const response = await window.AuthApp.apiFetch('/api/register', {
        method: 'POST',
        body: JSON.stringify({ name, email, password }),
      });

      if (response.ok && response.data.success) {
        showAlert('Registration successful! Redirecting to login...', 'success');
        form.reset();
        setTimeout(() => {
          window.location.href = `/login.html?registered_email=${encodeURIComponent(email)}`;
        }, 1200);
      } else {
        showAlert(response.data.error || 'Registration failed. Please check your inputs.', 'error');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Register Account';
      }
    } catch (err) {
      showAlert('Network error: Unable to contact the authentication server.', 'error');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Register Account';
    }
  });
});
