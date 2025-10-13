const express = require('express');

const authMiddleware = require('../middlewares/authMiddleware');
const {
	register,
	login,
	checkLockout,
	anonymousLogin,
	resendVerificationEmail,
	verifyEmail,
	updateProfile,
	logout,
	upgradeAnonymousUser,
	anonymousUserRegistration,
} = require('../controllers/authController');
const {
	socialMediaLogin,
	passwordRecovery,
	verifyResetPasswordOTP,
	resetPassword,
	invalidateOtherSessions,
	addToWhitelist,
	updateContactInfo,
	getAllUsers,
	deactivateAccount,
	deleteAccount,
} = require('../controllers/XAuthController');

const router = express.Router();

// Public Routes
router.post('/register', register);
router.post('/login', checkLockout, login);
router.post('/anonymous-register', anonymousUserRegistration);
router.post('/anonymous-login', anonymousLogin);
router.post('/social-login', socialMediaLogin);
router.post('/password-recovery', passwordRecovery);
router.post('/verifyresetotp', verifyResetPasswordOTP);
router.post('/resetpassword', resetPassword);

// Email Verification Routes
router.post('/resend-verification', resendVerificationEmail);
router.post('/verify-email', verifyEmail);

// Protected Routes (require authentication)
router.put('/updateprofile', authMiddleware, updateProfile);
router.post('/logout', authMiddleware, logout);
router.post('/invalidate-sessions', authMiddleware, invalidateOtherSessions);
router.post('/whitelist', authMiddleware, addToWhitelist);
router.put('/update-contact-info', authMiddleware, updateContactInfo);
// Get all users in database
router.get('/users', authMiddleware, getAllUsers);

// Account Management Routes
router.post('/deactivate', authMiddleware, deactivateAccount);
router.delete('/delete', authMiddleware, deleteAccount);

// Anonymous user to normal user upgrade
router.post('/switch-usertype', authMiddleware, upgradeAnonymousUser);

module.exports = router;
