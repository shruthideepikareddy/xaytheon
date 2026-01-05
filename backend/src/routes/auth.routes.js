const express = require("express");
const router = express.Router();

const controller = require("../controllers/auth.controller");
const { verifyAccessToken, loginRateLimiter } = require("../middleware/auth.middleware");

router.post("/register", controller.register);
router.post("/login", loginRateLimiter, controller.login);
router.post("/refresh", controller.refresh);
router.post("/logout", controller.logout);
router.get("/verify", verifyAccessToken, controller.verifyToken);

module.exports = router;
