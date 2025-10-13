const express = require('express');
const { sendOTP, verifyOTP } = require('../controllers/otpController');

const router = express.Router();

router.post('/send', sendOTP); // Send OTP to user
router.post('/verify', verifyOTP); // Verify OTP

module.exports = router;
