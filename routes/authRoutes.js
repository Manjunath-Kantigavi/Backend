const express = require('express');
const router = express.Router();
const { login, register, getMe, verifyAdmin } = require('../controllers/authController');
const { protect, authorize } = require('../middlewares/authMiddleware');

// Auth routes
router.post('/register', register);
router.post('/login', login);
router.get('/me', protect, getMe);
router.get('/verify-admin', protect, authorize('admin'), verifyAdmin);

module.exports = router;
