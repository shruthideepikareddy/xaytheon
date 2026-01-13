// Ensure global namespace exists immediately
window.XAYTHEON_AUTH = window.XAYTHEON_AUTH || {};

(function () {
  console.log("Xaytheon Auth Script Loaded"); // Debug log

  // For local dev, using 127.0.0.1 is safer than localhost to avoid IPv6 issues
  const API_BASE_URL = "http://127.0.0.1:5000/api/auth";

  const REQUEST_TIMEOUT = 30000;

  async function fetchWithTimeout(resource, options = {}) {
    const { timeout = REQUEST_TIMEOUT } = options;
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    const response = await fetch(resource, {
      ...options,
      signal: controller.signal
    });
    clearTimeout(id);
    return response;
  }

  let accessToken = null;
  let currentUser = null;
  let tokenExpiryTime = null;
  let refreshTimer = null;
  let lastAuthError = null;

  function setAccessToken(token, expiresIn, user) {
    accessToken = token;
    if (user) currentUser = user;
    tokenExpiryTime = Date.now() + (expiresIn - 60) * 1000;
    lastAuthError = null; // Clear error on success
    scheduleTokenRefresh();
    window.dispatchEvent(new CustomEvent('xaytheon:authchange', { detail: { user: currentUser } }));
  }

  function getSession() {
    return {
      user: currentUser,
      accessToken: accessToken,
    };
  }

  function clearAccessToken() {
    accessToken = null;
    currentUser = null;
    tokenExpiryTime = null;
    if (refreshTimer) clearTimeout(refreshTimer);
    localStorage.removeItem("x_refresh_token");
    window.dispatchEvent(new CustomEvent('xaytheon:authchange', { detail: { user: null } }));
  }

  async function refreshAccessToken() {
    try {
      const storedRefreshToken = localStorage.getItem("x_refresh_token");

      const options = {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      };

      if (storedRefreshToken) {
        options.body = JSON.stringify({ refreshToken: storedRefreshToken });
      } else {
        options.credentials = "include";
      }

      const res = await fetchWithTimeout(`${API_BASE_URL}/refresh`, options);

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.message || "Token refresh failed");
      }

      const data = await res.json();
      setAccessToken(data.accessToken, data.expiresIn, data.user);

      if (data.refreshToken) {
        localStorage.setItem("x_refresh_token", data.refreshToken);
      }

      return true;
    } catch (err) {
      console.warn("Session restore failed:", err);
      lastAuthError = err.message; // Capture error for UI

      if (!err.message.includes("Network")) {
        if (err.message.includes("Invalid") || err.message.includes("expired") || err.message.includes("not found")) {
          // Only clear if explicitly invalid, but keep error for display
          accessToken = null;
          currentUser = null;
          localStorage.removeItem("x_refresh_token");
        }
      }
      renderAuthArea(); // Update UI to show error
      return false;
    }
  }

  function scheduleTokenRefresh() {
    if (refreshTimer) clearTimeout(refreshTimer);

    if (!tokenExpiryTime) return;

    const timeUntilRefresh = tokenExpiryTime - Date.now();
    if (timeUntilRefresh > 0) {
      refreshTimer = setTimeout(() => {
        refreshAccessToken();
      }, timeUntilRefresh);
    }
  }

  async function authenticatedFetch(url, options = {}) {
    if (isTokenExpiringSoon()) {
      const refreshed = await refreshAccessToken();
      if (!refreshed) {
        throw new Error("Authentication required");
      }
    }

    const token = getAccessToken();
    if (!token) {
      throw new Error("No access token available");
    }

    const headers = {
      ...options.headers,
      "Authorization": `Bearer ${token}`,
    };

    const response = await fetchWithTimeout(url, {
      ...options,
      headers,
      credentials: "include",
    });

    if (response.status === 401) {
      const data = await response.json();
      if (data.expired) {
        const refreshed = await refreshAccessToken();
        if (refreshed) {
          // Retry request with new token
          headers.Authorization = `Bearer ${getAccessToken()}`;
          return fetch(url, { ...options, headers, credentials: "include" });
        }
      }
    }

    return response;
  }

  function isAuthenticated() {
    return accessToken !== null;
  }

  async function login(email, password) {
    // Input validation
    if (!email || typeof email !== 'string' || !password || typeof password !== 'string') {
      throw new Error('Email and password are required');
    }

    if (email.length > 254 || password.length > 128) {
      throw new Error('Input data too long');
    }

    if (email.length < 3 || password.length < 8) {
      throw new Error('Input data too short');
    }

    try {
      const res = await fetchWithTimeout(`${API_BASE_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email: email.trim(), password }),
      });

      if (!res.ok) {
        let errorMessage = "Login failed";
        try {
          const err = await res.json();
          errorMessage = err.message || errorMessage;
        } catch {
          // If we can't parse the error response, use status text
          errorMessage = res.statusText || errorMessage;
        }

        // Handle specific HTTP status codes
        if (res.status === 429) {
          throw new Error('Too many login attempts. Please wait before trying again.');
        } else if (res.status === 401) {
          throw new Error('Invalid email or password');
        } else if (res.status >= 500) {
          throw new Error('Server error. Please try again later.');
        }

        throw new Error(errorMessage);
      }

      const data = await res.json();

      // Validate response data
      if (!data.accessToken || !data.user) {
        throw new Error('Invalid response from server');
      }

      setAccessToken(data.accessToken, data.expiresIn, data.user);

      if (data.refreshToken) {
        localStorage.setItem("x_refresh_token", data.refreshToken);
      }

      renderAuthArea();
      applyAuthGating();
    } catch (err) {
      if (err.message.includes('timeout')) {
        throw new Error('Request timeout. Please check your connection.');
      }
      if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
        throw new Error('Network error. Please check your connection.');
      }
      // Re-throw the original error if it's already user-friendly
      throw err;
    }
  }

  async function register(email, password) {
    // Input validation
    if (!email || typeof email !== 'string' || !password || typeof password !== 'string') {
      throw new Error('Email and password are required');
    }

    if (email.length > 254 || password.length > 128) {
      throw new Error('Input data too long');
    }

    if (email.length < 3 || password.length < 8) {
      throw new Error('Input data too short');
    }

    try {
      const res = await fetchWithTimeout(`${API_BASE_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password }),
      });

      if (!res.ok) {
        let errorMessage = "Registration failed";
        try {
          const err = await res.json();
          errorMessage = err.message || errorMessage;
        } catch {
          // If we can't parse the error response, use status text
          errorMessage = res.statusText || errorMessage;
        }

        // Handle specific HTTP status codes
        if (res.status === 409) {
          throw new Error('An account with this email already exists');
        } else if (res.status === 429) {
          throw new Error('Too many registration attempts. Please wait before trying again.');
        } else if (res.status >= 500) {
          throw new Error('Server error. Please try again later.');
        }

        throw new Error(errorMessage);
      }

      const data = await res.json();
      return data;
    } catch (err) {
      if (err.message.includes('timeout')) {
        throw new Error('Request timeout. Please check your connection.');
      }
      if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
        throw new Error('Network error. Please check your connection.');
      }
      // Re-throw the original error if it's already user-friendly
      throw err;
    }
  }

  async function logout() {
    try {
      await fetchWithTimeout(`${API_BASE_URL}/logout`, {
        method: "POST",
        credentials: "include",
      });
    } catch (err) {
      console.error("Logout error:", err);
    }

    clearAccessToken();
    renderAuthArea();
    applyAuthGating();
    // Force reload to clear any private state
    window.location.reload();
  }

  async function restoreSession() {
    // If we have a stored refresh token, try to use it
    if (localStorage.getItem("x_refresh_token")) {
      try {
        await refreshAccessToken();
      } catch (err) {
        console.log("No existing session restored");
        lastAuthError = err.message;
        renderAuthArea();
      }
    }
  }

  function renderAuthArea() {
    const container = document.getElementById("auth-area");
    if (!container) return;

    if (!isAuthenticated()) {
      if (lastAuthError) {
        // Show error next to sign in button
        container.innerHTML = `
           <div style="display:flex; align-items:center; gap:10px;">
             <span style="color:#ef4444; font-size:11px; max-width:150px; line-height:1.2;">
               ${lastAuthError}
             </span>
             <a class="btn btn-outline" href="login.html">Sign in</a>
           </div>
         `;
      } else {
        container.innerHTML = '<a class="btn btn-outline" href="login.html">Sign in</a>';
      }
      return;
    }

    container.innerHTML = `
      <div class="user-menu">
        <button class="user-button" id="user-button">
          <span class="user-avatar">U</span>
          <span class="chev">▾</span>
        </button>
        <div class="user-dropdown" id="user-dropdown" hidden>
          <button class="dropdown-item" id="sign-out-btn">Sign out</button>
        </div>
      </div>
    `;

    const btn = document.getElementById("user-button");
    const dd = document.getElementById("user-dropdown");
    const signOutBtn = document.getElementById("sign-out-btn");

    if (btn && dd && signOutBtn) {
      btn.addEventListener("click", () => {
        dd.toggleAttribute("hidden");
      });

      signOutBtn.addEventListener("click", logout);
    }
  }

  function applyAuthGating() {
    const authed = isAuthenticated();

    document
      .querySelectorAll("[data-requires-auth]")
      .forEach((el) => (el.style.display = authed ? "" : "none"));

    document
      .querySelectorAll("[data-requires-guest]")
      .forEach((el) => (el.style.display = authed ? "none" : ""));
  }

  // Assign methods to the global object
  Object.assign(window.XAYTHEON_AUTH, {
    getSession,
    login,
    register,
    logout,
    authenticatedFetch
  });

  window.addEventListener("DOMContentLoaded", async () => {
    await restoreSession();
    renderAuthArea();
    applyAuthGating();
  });

  window.addEventListener("beforeunload", () => {
    // Tokens cleared automatically on page close
  });

  // Ensure XAYTHEON_AUTH exists
  window.XAYTHEON_AUTH = window.XAYTHEON_AUTH || {};

  /**
   * Request password reset (forgot password)
   * @param {string} email - User's email address
   */
  window.XAYTHEON_AUTH.forgotPassword = async function (email) {
    try {
      const response = await fetch(`${API_BASE_URL}/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || "Failed to send reset email");
      }

      return data;
    } catch (error) {
      console.error("Forgot password error:", error);
      throw error;
    }
  };

  /**
   * Reset password using token
   * @param {string} token - Reset token from email
   * @param {string} newPassword - New password
   */
  window.XAYTHEON_AUTH.resetPassword = async function (token, newPassword) {
    try {
      const response = await fetch(`${API_BASE_URL}/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, newPassword }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || "Failed to reset password");
      }

      return data;
    } catch (error) {
      console.error("Reset password error:", error);
      throw error;
    }
  };

  /**
   * Validate reset token
   * @param {string} token - Reset token to validate
   */
  window.XAYTHEON_AUTH.validateResetToken = async function (token) {
    try {
      const response = await fetch(`${API_BASE_URL}/validate-reset-token?token=${encodeURIComponent(token)}`, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      });

      const data = await response.json();

      if (!response.ok || !data.valid) {
        throw new Error(data.message || "Invalid token");
      }

      return data;
    } catch (error) {
      console.error("Validate token error:", error);
      throw error;
    }
  };

})();
