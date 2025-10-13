const User = require('../models/User');
const Token = require('../models/token');
const UserResetOTP = require('../models/userResetOtp');
const sendEmail = require('../utils/emailService');
const { verifyToken, generateToken } = require('../utils/jwt');
const generateHimeNumber = require('../services/himeNumberService');
const { generateOTP, saveOTP } = require('../utils/otpService');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// socialMediaLogin
exports.socialMediaLogin = async (req, res) => {
	try {
		const { token, provider } = req.body;

		if (provider !== 'google') {
			return res.status(400).json({ message: 'Unsupported provider' });
		}

		// Verify Google Token
		const ticket = await googleClient.verifyIdToken({
			idToken: token,
			audience: process.env.GOOGLE_CLIENT_ID,
		});
		const payload = ticket.getPayload();
		const { sub: providerId, email, name: username } = payload;

		// Find or create user based on providerId
		let user = await User.findOne({ provider, providerId });
		if (!user) {
			user = await User.create({
				email,
				username,
				provider,
				providerId,
				himeNumber: generateHimeNumber(1),
				userType: 'normal',
				emailVerified: true,
			});
		}

		// Generate JWT
		const authToken = generateToken({ id: user._id });
		res.status(200).json({
			message: 'Social Media Login successful',
			token: authToken,
			user: generateUserResponse(user),
		});
	} catch (error) {
		return handleError(res, error, 'Error during social media login');
	}
};

// Password recovery
exports.passwordRecovery = async (req, res) => {
	try {
		const { email } = req.body;
		const user = await User.findOne({ email });
		if (!user) return res.status(404).json({ message: 'User not found' });

		// const token = generateToken({ id: user._id }, '1h'); // Expires in 1 hour
		// const resetUrl = `${process.env.BASE_URL}/reset-password/${token}`;
		// await sendEmail(
		// 	user.email,
		// 	'Password Recovery',
		// 	`Reset your password: ${resetUrl}`,
		// 	`The link expires in an hour`,
		// );

		// res.status(200).json({ message: 'Password recovery email sent' });

		const otp = generateOTP();
		// Remove any existing OTP records for this user
		await UserResetOTP.deleteMany({ userId: user._id });
		// Create new OTP record
		await UserResetOTP.create({
			userId: user._id,
			email: user.email,
			otp,
		});
		// Send OTP via email

		await sendEmail(
			user.email,
			'Password Recovery OTP',
			`Your OTP for password reset is: ${otp}`,
			'This OTP is valid for 10 minutes',
		);

		res.status(200).json({
			message: 'OTP has been sent to your email',
			email: user.email,
		});
	} catch (error) {
		return handleError(res, error, 'Error during password recovery');
	}
};

exports.verifyResetPasswordOTP = async (req, res) => {
	try {
		const { email, otp } = req.body;

		// Find OTP record
		const resetRecord = await UserResetOTP.findOne({
			email,
			otp,
		}).populate('userId');

		if (!resetRecord) {
			return res.status(400).json({ message: 'Invalid or expired OTP' });
		}

		// Invalidate any existing reset tokens for this user
		await Token.updateMany(
			{
				userId: resetRecord.userId._id,
				type: 'reset',
				isValid: true,
			},
			{ isValid: false },
		);

		// Generate a short-lived token for password reset
		const tempToken = generateToken({ id: resetRecord.userId._id });
		// Store token in database
		const tokenDocument = new Token({
			userId: resetRecord.userId._id,
			token: tempToken,
			isValid: true,
			expiresAt: new Date(Date.now() + 5 * 60 * 1000), //  5min from now
			device: req.headers['user-agent'] || 'unknown',
			type: 'reset',
		});

		await tokenDocument.save();

		res.status(200).json({
			message: 'OTP verified successfully',
			token: tempToken,
		});
	} catch (error) {
		return handleError(res, error, 'Error verifying OTP');
	}
};

// Reset Password
exports.resetPassword = async (req, res) => {
	try {
		const { token, newPassword } = req.body;

		// Find token record
		const tokenRecord = await Token.findOne({
			token,
			isValid: true,
			type: 'reset',
			expiresAt: { $gt: new Date() },
		});

		if (!tokenRecord) {
			return res
				.status(400)
				.json({ message: 'Invalid or expired reset token' });
		}

		// Find user directly using the User model instead of using populated data
		const user = await User.findById(tokenRecord.userId);
		if (!user) {
			return res.status(404).json({ message: 'User not found' });
		}

		// Hash and update password
		user.password = await bcrypt.hash(newPassword, 10);
		await user.save();

		// Invalidate the used token
		tokenRecord.isValid = false;
		await tokenRecord.save();

		// Clean up OTP record
		await UserResetOTP.deleteMany({ userId: user._id });

		res.status(200).json({ message: 'Password has been reset successfully' });
	} catch (error) {
		console.error('Reset password error:', error);
		return handleError(res, error, 'Error resetting password');
	}
};

// Session Management
exports.invalidateOtherSessions = async (req, res) => {
	try {
		const { userId } = req.user;
		await Token.deleteMany({ userId, type: 'access' }); // Logout all sessions
		res.status(200).json({ message: 'All other sessions invalidated' });
	} catch (error) {
		return handleError(res, error, 'Error invalidating sessions');
	}
};
// Device and IP Whitelisting
exports.verifyDeviceAndIP = async (req, res, next) => {
	const { deviceId, ip } = req.body;
	const user = await User.findById(req.user.id);
	if (!user.whitelist.includes(deviceId) && !user.whitelist.includes(ip)) {
		return res.status(403).json({ message: 'Device or IP not authorized' });
	}
	next();
};

exports.addToWhitelist = async (req, res) => {
	try {
		const { deviceId, ip } = req.body;
		const user = await User.findById(req.user.id);
		user.whitelist.push(deviceId, ip);
		await user.save();
		res.status(200).json({ message: 'Device/IP added to whitelist' });
	} catch (error) {
		return handleError(res, error, 'Error adding to whitelist');
	}
};
// Role-Based Access Control (RBAC)
exports.checkRole = (roles) => (req, res, next) => {
	if (!roles.includes(req.user.role)) {
		return res.status(403).json({ message: 'Access denied' });
	}
	next();
};

//  Email and Phone Number Updates
exports.updateContactInfo = async (req, res) => {
	try {
		const { email, phone } = req.body;
		const user = await User.findById(req.user.id);

		if (email) {
			const emailInUse = await User.findOne({ email });
			if (emailInUse)
				return res.status(400).json({ message: 'Email is already in use' });
			user.email = email;
		}
		if (phone) user.phone = phone;

		await user.save();
		res.status(200).json({ message: 'Contact info updated successfully' });
	} catch (error) {
		return handleError(res, error, 'Error updating contact info');
	}
};
// Account Deactivation and Deletion
exports.deactivateAccount = async (req, res) => {
	try {
		const userId = req.user.id;

		// Fetch the user
		const user = await User.findById(userId);
		if (!user) {
			return res.status(404).json({ message: 'User not found' });
		}

		// Update user status and invalidate sessions in parallel
		const updates = {
			isActive: false,
			deactivatedAt: new Date(),
			lastActive: new Date(),
		};

		const [updatedUser] = await Promise.all([
			User.findByIdAndUpdate(userId, updates, { new: true }),
			Token.updateMany({ userId }, { isValid: false }),
		]);

		return res.status(200).json({
			message: 'Account successfully deactivated',
			deactivatedAt: updatedUser.deactivatedAt,
			reactivationInfo:
				'You can reactivate your account by logging in within 30 days',
		});
	} catch (error) {
		return handleError(res, error, 'Error deactivating account');
	}
};

exports.deleteAccount = async (req, res) => {
	try {
		await User.findByIdAndDelete(req.user.id);
		res.status(200).json({ message: 'Account deleted successfully' });
	} catch (error) {
		return handleError(res, error, 'Error deleting account');
	}
};

// Daily and Weekly Login Reports
exports.loginReports = async (req, res) => {
	try {
		const logins = await LoginActivity.aggregate([
			{
				$match: {
					userId: req.user.id,
					date: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }, // Last 7 days
				},
			},
			{ $group: { _id: '$date', count: { $sum: 1 } } },
		]);
		res.status(200).json(logins);
	} catch (error) {
		return handleError(res, error, 'Error generating login report');
	}
};
// Get All Users
exports.getAllUsers = async (req, res) => {
	try {
		// Verify the requesting user
		const requestingUser = await User.findById(req.user.id);
		if (!requestingUser) {
			return res.status(401).json({
				message: 'Authentication failed',
				details: 'User not found',
			});
		}

		// Check if the user has the 'admin' role
		if (requestingUser.role !== 'admin') {
			return res.status(403).json({
				message: 'Access denied',
				details: 'You do not have permission to view this resource',
			});
		}

		const {
			page = 1,
			limit = 10,
			userType,
			searchQuery,
			sortBy = 'createdAt',
			sortOrder = 'desc',
		} = req.query;

		// Build filter object
		const filter = {};
		if (userType) filter.userType = userType;
		if (searchQuery) {
			filter.$or = [
				{ username: { $regex: searchQuery, $options: 'i' } },
				{ himeNumber: { $regex: searchQuery, $options: 'i' } },
				{ email: { $regex: searchQuery, $options: 'i' } },
			];
		}

		// Calculate skip value for pagination
		const skip = (parseInt(page) - 1) * parseInt(limit);

		// Build sort object
		const sort = {};
		sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

		// Get total count for pagination
		const totalUsers = await User.countDocuments(filter);

		// Fetch users with pagination, filtering, and sorting
		const users = await User.find(filter)
			.select('-password -failedAttempts -lockUntil -whitelist')
			.sort(sort)
			.skip(skip)
			.limit(parseInt(limit));

		res.status(200).json({
			message: 'Users retrieved successfully',
			data: {
				users,
				currentPage: parseInt(page),
				totalPages: Math.ceil(totalUsers / parseInt(limit)),
				totalUsers,
				usersPerPage: parseInt(limit),
			},
		});
	} catch (error) {
		console.error('GetAllUsers Error:', error);
		return handleError(res, error, 'Error fetching users');
	}
};
