(function () {
  const API_BASE_URL =
    window.location.protocol === "https:"
      ? "https://your-api-domain.com/api/auth"
      : "http://localhost:5000/api/auth";

  const REQUEST_TIMEOUT = 30000;

  async function fetchWithTimeout(url, options = {}, timeout = REQUEST_TIMEOUT) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      return response;
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === "AbortError") {
        throw { code: "TIMEOUT" };
      }
      throw err;
    }
  }

  let accessToken = null;
  let currentUser = null;
  let tokenExpiryTime = null;
  let refreshTimer = null;

  function setAccessToken(token, expiresIn, user) {
    accessToken = token;
    currentUser = user || null;
    tokenExpiryTime = Date.now() + (expiresIn - 60) * 1000;
    scheduleTokenRefresh();

    window.dispatchEvent(
      new CustomEvent("xaytheon:authchange", {
        detail: { user: currentUser },
      })
    );
  }

  function clearAccessToken() {
    accessToken = null;
    currentUser = null;
    tokenExpiryTime = null;
    localStorage.removeItem("x_refresh_token");

    if (refreshTimer) {
      clearTimeout(refreshTimer);
      refreshTimer = null;
    }

    window.dispatchEvent(
      new CustomEvent("xaytheon:authchange", {
        detail: { user: null },
      })
    );
  }

  function isTokenExpiringSoon() {
    return !tokenExpiryTime || Date.now() >= tokenExpiryTime;
  }

  async function refreshAccessToken() {
    try {
      const refreshToken = localStorage.getItem("x_refresh_token");
      if (!refreshToken) throw { code: "SESSION_EXPIRED" };

      const res = await fetchWithTimeout(`${API_BASE_URL}/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken }),
      });

      if (!res.ok) throw { code: "SESSION_EXPIRED" };

      const data = await res.json();
      setAccessToken(data.accessToken, data.expiresIn, data.user);

      if (data.refreshToken) {
        localStorage.setItem("x_refresh_token", data.refreshToken);
      }

      return true;
    } catch {
      clearAccessToken();
      return false;
    }
  }

  function scheduleTokenRefresh() {
    if (refreshTimer) clearTimeout(refreshTimer);
    if (!tokenExpiryTime) return;

    refreshTimer = setTimeout(refreshAccessToken, tokenExpiryTime - Date.now());
  }

  async function authenticatedFetch(url, options = {}) {
    if (isTokenExpiringSoon()) {
      const ok = await refreshAccessToken();
      if (!ok) throw { code: "SESSION_EXPIRED" };
    }

    const res = await fetchWithTimeout(url, {
      ...options,
      headers: {
        ...options.headers,
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (res.status === 401) throw { code: "UNAUTHORIZED" };
    return res;
  }

  async function login(email, password) {
    if (!email || !password) throw { code: "INVALID_INPUT" };

    try {
      const res = await fetchWithTimeout(`${API_BASE_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password }),
      });

      if (!res.ok) {
        if (res.status === 401) throw { code: "INVALID_CREDENTIALS" };
        if (res.status === 429) throw { code: "TOO_MANY_ATTEMPTS" };
        if (res.status >= 500) throw { code: "SERVER_ERROR" };
        throw { code: "AUTH_FAILED" };
      }

      const data = await res.json();
      setAccessToken(data.accessToken, data.expiresIn, data.user);

      if (data.refreshToken) {
        localStorage.setItem("x_refresh_token", data.refreshToken);
      }
    } catch (err) {
      if (err.message?.includes("Failed to fetch")) {
        throw { code: "NETWORK_ERROR" };
      }
      throw err;
    }
  }

  async function register(email, password) {
    if (!email || !password) throw { code: "INVALID_INPUT" };

    try {
      const res = await fetchWithTimeout(`${API_BASE_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password }),
      });

      if (!res.ok) {
        if (res.status === 409) throw { code: "USER_EXISTS" };
        if (res.status === 429) throw { code: "TOO_MANY_ATTEMPTS" };
        if (res.status >= 500) throw { code: "SERVER_ERROR" };
        throw { code: "AUTH_FAILED" };
      }

      return await res.json();
    } catch (err) {
      if (err.message?.includes("Failed to fetch")) {
        throw { code: "NETWORK_ERROR" };
      }
      throw err;
    }
  }

  async function logout() {
    try {
      await fetchWithTimeout(`${API_BASE_URL}/logout`, { method: "POST" });
    } catch {}
    clearAccessToken();
    window.location.reload();
  }

  window.XAYTHEON_AUTH = {
    login,
    register,
    logout,
    authenticatedFetch,
    isAuthenticated: () => !!accessToken,
  };
})();

/* =========================
   CENTRALIZED ERROR HANDLER
   ========================= */

function getAuthErrorMessage(error) {
  if (!error) return "Something went wrong. Please try again.";

  switch (error.code) {
    case "INVALID_CREDENTIALS":
      return "Invalid email or password.";
    case "USER_EXISTS":
      return "An account with this email already exists.";
    case "INVALID_INPUT":
      return "Please enter valid email and password.";
    case "NETWORK_ERROR":
      return "Network error. Please check your connection.";
    case "SESSION_EXPIRED":
      return "Your session has expired. Please login again.";
    case "UNAUTHORIZED":
      return "You are not authorized. Please login.";
    case "TOO_MANY_ATTEMPTS":
      return "Too many attempts. Please wait and try again.";
    case "SERVER_ERROR":
      return "Server error. Please try again later.";
    case "TIMEOUT":
      return "Request timed out. Please try again.";
    default:
      return "Authentication failed. Please try again.";
  }
}
