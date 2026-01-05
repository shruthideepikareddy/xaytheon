(function () {
  const API_BASE_URL = window.location.protocol === "https:" 
    ? "https://your-api-domain.com/api/auth"
    : "http://localhost:5000/api/auth";

  const REQUEST_TIMEOUT = 30000;

  async function fetchWithTimeout(url, options = {}, timeout = REQUEST_TIMEOUT) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      return response;
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        throw new Error('Request timeout. Please check your connection.');
      }
      throw err;
    }
  }

  let accessToken = null;
  let tokenExpiryTime = null;
  let refreshTimer = null;

  function setAccessToken(token, expiresIn) {
    accessToken = token;
    tokenExpiryTime = Date.now() + (expiresIn - 60) * 1000;
    scheduleTokenRefresh();
  }

  function clearAccessToken() {
    accessToken = null;
    tokenExpiryTime = null;
    if (refreshTimer) {
      clearTimeout(refreshTimer);
      refreshTimer = null;
    }
  }

  function getAccessToken() {
    return accessToken;
  }

  function isTokenExpiringSoon() {
    if (!tokenExpiryTime) return true;
    return Date.now() >= tokenExpiryTime;
  }

  async function refreshAccessToken() {
    try {
      const res = await fetchWithTimeout(`${API_BASE_URL}/refresh`, {
        method: "POST",
        credentials: "include", // Send httpOnly cookies
        headers: { "Content-Type": "application/json" },
      });

      if (!res.ok) {
        throw new Error("Token refresh failed");
      }

      const data = await res.json();
      setAccessToken(data.accessToken, data.expiresIn);
      return true;
    } catch (err) {
      console.error("Token refresh error:", err);
      clearAccessToken();
      renderAuthArea();
      applyAuthGating();
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
    try {
      const res = await fetchWithTimeout(`${API_BASE_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email, password }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.message || "Login failed");
      }

      const data = await res.json();
      setAccessToken(data.accessToken, data.expiresIn);
      renderAuthArea();
      applyAuthGating();
    } catch (err) {
      if (err.message.includes('timeout')) {
        throw new Error('Request timeout. Please check your connection.');
      }
      if (err.message.includes('Failed to fetch')) {
        throw new Error('Network error. Please check your connection.');
      }
      throw err;
    }
  }

  async function register(email, password) {
    try {
      const res = await fetchWithTimeout(`${API_BASE_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.message || "Registration failed");
      }

      return res.json();
    } catch (err) {
      if (err.message.includes('timeout')) {
        throw new Error('Request timeout. Please check your connection.');
      }
      if (err.message.includes('Failed to fetch')) {
        throw new Error('Network error. Please check your connection.');
      }
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
  }

  async function restoreSession() {
    try {
      await refreshAccessToken();
    } catch (err) {
      console.log("No existing session");
    }
  }

  function renderAuthArea() {
    const container = document.getElementById("auth-area");
    if (!container) return;

    if (!isAuthenticated()) {
      container.innerHTML =
        '<a class="btn btn-outline" href="login.html">Sign in</a>';
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

    btn.addEventListener("click", () => {
      dd.toggleAttribute("hidden");
    });

    signOutBtn.addEventListener("click", logout);
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

  function enforceHttps() {
    if (window.location.protocol !== "https:" && 
        window.location.hostname !== "localhost" &&
        window.location.hostname !== "127.0.0.1") {
      // In production, redirect to HTTPS
      if (process.env.NODE_ENV === "production") {
        window.location.protocol = "https:";
      } else {
        console.warn("⚠️ WARNING: Using HTTP in non-local environment. Switch to HTTPS for security.");
      }
    }
  }

  window.XAYTHEON_AUTH = {
    login,
    register,   
    logout,
    isAuthenticated,
    authenticatedFetch,
    refreshAccessToken,
  };

  window.addEventListener("DOMContentLoaded", async () => {
    enforceHttps();
    await restoreSession();
    renderAuthArea();
    applyAuthGating();
  });

  window.addEventListener("beforeunload", () => {
    // Tokens cleared automatically on page close
  });
})();
