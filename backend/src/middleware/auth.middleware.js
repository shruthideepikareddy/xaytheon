const jwt = require("jsonwebtoken");

exports.verifyAccessToken = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Access token required" });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.type !== "access") {
      return res.status(401).json({ message: "Invalid token type" });
    }

    req.userId = decoded.id;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ 
        message: "Access token expired",
        expired: true 
      });
    }
    
    return res.status(401).json({ message: "Invalid access token" });
  }
};

exports.loginRateLimiter = (() => {
  const attempts = new Map();
  const MAX_ATTEMPTS = 5;
  const WINDOW_MS = 15 * 60 * 1000;

  return (req, res, next) => {
    const identifier = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    
    if (!attempts.has(identifier)) {
      attempts.set(identifier, []);
    }

    const userAttempts = attempts.get(identifier);
    const recentAttempts = userAttempts.filter(time => now - time < WINDOW_MS);

    if (recentAttempts.length >= MAX_ATTEMPTS) {
      return res.status(429).json({ 
        message: "Too many login attempts. Please try again later." 
      });
    }

    recentAttempts.push(now);
    attempts.set(identifier, recentAttempts);
    next();
  };
})();
