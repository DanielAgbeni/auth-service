const User = require('../models/User');
const Token = require('../models/token');
const sendEmail = require('../utils/emailService');
const { verifyToken, generateToken } = require('../utils/jwt');
const generateHimeNumber = require('../services/himeNumberService');
const bcrypt = require('bcryptjs');

const {
	generateUserResponse,
	handleError,
	handleRegistration,
	findUserByIdentifier,
	createToken,
	sendVerificationEmail,
} = require('../utils/helper');

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_TIME = 30 * 60 * 1000; // 30 minutes

// Register Traditional User
// Assuming imports for User, bcrypt, handleError, createToken (as auth token),
// and a (commented out) sendVerificationEmail
// const User = require('../models/User');
// const bcrypt = require('bcryptjs');
// const { handleError } = require('../utils/errorHelper');
// const { createToken } = require('../services/tokenService'); // Assuming this is an AUTH token
// const { sendVerificationEmail } = require('../services/emailService');

exports.register = async (req, res) => {
	try {
		const {
			email,
			username,
			password,
			userType,
			himeNumber, // Added this, as you use it in the User model
			verificationMethod,
		} = req.body;

		// 1. Validate userType first
		if (!['normal', 'anonymous'].includes(userType)) {
			return res.status(400).json({
				message: "Invalid userType. Allowed values: 'normal' or 'anonymous'.",
			});
		}

		// --- BRANCH 1: Normal User Registration ---
		if (userType === 'normal') {
			// 1a. Validate required fields for 'normal' users
			if (!email || !password) {
				return res.status(400).json({
					message: 'Email and password are required for normal users.',
				});
			}

			// 1b. Hash password
			const hashedPassword = await bcrypt.hash(password, 10);

			// 1c. Create new user
			const user = new User({
				email,
				password: hashedPassword,
				username,
				himeNumber, // Now correctly passed
				userType: 'normal', // Explicitly set
				role: 'user',
			});
			await user.save();

			// 1d. Handle Verification
			const verificationMethodFinal = verificationMethod || 'otp';
			// We assume createToken makes a verification token or OTP here
			// const verificationToken = await createVerificationToken(user._id);

			// Mocking the email send to avoid load test issues
			// await sendVerificationEmail(user, verificationMethodFinal, verificationToken);

			// 1e. Send response
			return res.status(201).json({
				message:
					'Registration successful. Please verify your email with the OTP sent.',
				userId: user._id,
				user: {
					id: user._id,
					email: user.email,
					username: user.username,
					himeNumber: user.himeNumber,
					userType: user.userType,
				},
			});
		}

		// --- BRANCH 2: Anonymous User Registration ---
		if (userType === 'anonymous') {
			// 2a. Create guest user
			const user = new User({
				// No email or password needed
				username: username || `Guest_${Date.now()}`, // Generate a guest username
				himeNumber,
				userType: 'anonymous', // Explicitly set
				role: 'user',
				isVerified: true, // Anonymous users don't need verification
			});
			await user.save();

			// 2b. Create an AUTH token to log them in immediately
			const authToken = await createToken(user._id, req.headers['user-agent']);

			// 2c. Send response with auth token
			return res.status(201).json({
				message: 'Anonymous user created successfully.',
				token: authToken, // Send auth token to log them in
				user: {
					id: user._id,
					username: user.username,
					himeNumber: user.himeNumber,
					userType: user.userType,
				},
			});
		}
	} catch (error) {
		// Handle duplicate key error (e.g., email or username already exists)
		if (error.code === 11000) {
			return res.status(409).json({
				message: 'An account with this email or username already exists.',
			});
		}
		return handleError(res, error, 'Unexpected error during registration');
	}
};

// Login
exports.login = async (req, res) => {
	try {
		const { email, username, himeNumber, password } = req.body;

		const user = await findUserByIdentifier(email || username || himeNumber);

		if (!user) {
			return res.status(404).json({
				message: 'No account found',
				details:
					'The provided email, username, or Hime Number does not match any existing account.',
			});
		}

		if (user.lockUntil && user.lockUntil > new Date()) {
			const remainingLockTime = Math.ceil(
				(user.lockUntil - new Date()) / 60000,
			);
			return res.status(403).json({
				message: 'Account temporarily locked',
				details: `Too many failed login attempts. Please try again in ${remainingLockTime} minutes.`,
				lockedUntil: user.lockUntil,
			});
		}

		const isPasswordValid = user.password
			? await bcrypt.compare(password, user.password)
			: false;

		if (!isPasswordValid) {
			user.failedAttempts = (user.failedAttempts || 0) + 1;
			if (user.failedAttempts >= 5) {
				user.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
				await user.save();
				try {
					await sendEmail(
						user.email,
						'Login blocked',
						`Dear ${user.username}, we've noticed too many failed login attempts. Your account has been temporarily locked for 15 minutes.`,
					);
				} catch (emailError) {
					console.error('Failed to send email:', emailError.message);
				}
				return res.status(401).json({
					message: 'Login blocked',
					details:
						'Too many failed login attempts. Your account has been temporarily locked for 15 minutes.',
					failedAttempts: user.failedAttempts,
					lockDuration: 15, // minutes
				});
			}
			await user.save();
			return res.status(401).json({
				message: 'Invalid credentials',
				details: 'The password you entered is incorrect.',
				remainingAttempts: 5 - user.failedAttempts,
			});
		}

		const token = await createToken(user._id, req.headers['user-agent']);

		user.failedAttempts = 0;
		user.lockUntil = undefined;
		user.lastLogin = new Date();
		await user.save();

		await Token.deleteMany({
			userId: user._id,
			expiresAt: { $lt: new Date() },
		});

		res.status(200).json({
			message: 'Login successful',
			token,
			user: generateUserResponse(user),
		});
	} catch (error) {
		return handleError(res, error, 'Unexpected error during login process');
	}
};

// Logout// Logout
exports.logout = async (req, res) => {
	try {
		const { token } = req.body;

		if (!token) {
			return res.status(400).json({ message: 'Token is required for logout.' });
		}

		// Find the token in the database
		const existingToken = await Token.findOne({ token });

		if (!existingToken || !existingToken.isValid) {
			return res.status(400).json({
				message: 'Token is invalid or already logged out.',
			});
		}

		// Mark the token as invalid
		existingToken.isValid = false;
		await existingToken.save();

		// Optionally, revoke all tokens for the user if this is a global logout
		// await Token.updateMany({ userId: existingToken.userId }, { isValid: false });

		res.status(200).json({ message: 'Logout successful.' });
	} catch (error) {
		return handleError(res, error, 'Error during logout');
	}
};

// Update Profile
exports.updateProfile = async (req, res) => {
	try {
		const userId = req.user.id;
		const {
			username,
			password,
			email,
			bio,
			gender,
			dateOfBirth,
			phone,
			country,
			state,
			city,
			zipCode,
			language,
			theme,
			avatarUrl,
		} = req.body;

		const user = await User.findById(userId);
		if (!user) {
			return res.status(404).json({ message: 'User not found' });
		}

		if (username) {
			const existingUser = await User.findOne({ username });
			if (existingUser && existingUser._id.toString() !== userId) {
				return res.status(400).json({ message: 'Username is already taken.' });
			}
			user.username = username;
		}

		if (password) {
			user.password = await bcrypt.hash(password, 10);
		}
		if (email) user.email = email;
		if (bio) user.bio = bio;
		if (gender) user.gender = gender;
		if (dateOfBirth) user.dateOfBirth = dateOfBirth;
		if (phone) user.phone = phone;
		if (country || state || city || zipCode) {
			user.address = {
				country: country || user.address.country,
				state: state || user.address.state,
				city: city || user.address.city,
				zipCode: zipCode || user.address.zipCode,
			};
		}
		if (language) user.preferences.language = language;
		if (theme) user.preferences.theme = theme;
		if (avatarUrl) user.avatarUrl = avatarUrl;

		await user.save();

		res.status(200).json({
			message: 'Profile updated successfully',
			user: generateUserResponse(user),
		});
	} catch (error) {
		return handleError(res, error, 'Error during profile update');
	}
};

// Resend Verification Email
exports.resendVerificationEmail = async (req, res) => {
	try {
		const { email, method } = req.body;

		const user = await User.findOne({ email });
		if (!user) return res.status(404).json({ message: 'User not found.' });

		if (user.emailVerified)
			return res.status(400).json({ message: 'Email already verified.' });

		if (method === 'token') {
			await Token.deleteMany({ userId: user._id });
			const token = generateToken({ id: user._id });
			await new Token({ userId: user._id, token }).save();
			await sendVerificationEmail(user, method, token);
		} else if (method === 'otp') {
			await sendVerificationEmail(user, method);
		}

		res.status(200).json({ message: 'Verification email sent successfully.' });
	} catch (error) {
		return handleError(res, error, 'Error during resend verification');
	}
};

// Verify Email
exports.verifyEmail = async (req, res) => {
	try {
		const { userId, token } = req.body;
		if (!userId || !token)
			return res.status(400).json({ message: 'Missing userId or token.' });

		const existingToken = await Token.findOne({ userId, token, isValid: true });
		if (!existingToken)
			return res.status(400).json({ message: 'Invalid or expired token.' });

		await Token.findOneAndUpdate(
			{ _id: existingToken._id },
			{ isValid: false },
		);

		await User.findByIdAndUpdate(userId, { emailVerified: true });

		res.status(200).json({ message: 'Email verified successfully.' });
	} catch (error) {
		return handleError(res, error, 'Error during email verification');
	}
};

// Anonymous User Registration/Login
exports.anonymousUserRegistration = async (req, res) => {
	try {
		const { username, password, userType = 'anonymous' } = req.body;

		if (!username || !password) {
			return res.status(400).json({
				message:
					'Username and password are required for anonymous user registration.',
			});
		}

		const existingUser = await User.findOne({ username });
		if (existingUser) {
			return res.status(400).json({
				message: 'Username is already taken.',
			});
		}

		const himeNumber = generateHimeNumber(userType);
		const hashedPassword = await bcrypt.hash(password, 10);

		const anonymousUser = await User.create({
			username,
			password: hashedPassword,
			himeNumber,
			userType,
			emailVerified: false,
		});

		const token = await createToken(
			anonymousUser._id,
			req.headers['user-agent'],
		);

		res.status(201).json({
			message: 'Anonymous user registered successfully',
			token,
			user: {
				id: anonymousUser._id,
				username: anonymousUser.username,
				himeNumber: anonymousUser.himeNumber,
			},
		});
	} catch (error) {
		return handleError(res, error, 'Error during anonymous user registration');
	}
};

// Anonymous User Login
exports.anonymousLogin = async (req, res) => {
	try {
		const { username, himeNumber, password } = req.body;

		const user = await User.findOne({
			$or: [{ username }, { himeNumber }],
			userType: 'anonymous',
		});

		if (!user) {
			return res.status(404).json({
				message: 'Anonymous user not found',
			});
		}

		if (!(await bcrypt.compare(password, user.password))) {
			return res.status(401).json({
				message: 'Invalid credentials',
			});
		}
		const token = await createToken(user._id, req.headers['user-agent']);

		res.status(200).json({
			message: 'Anonymous login successful',
			token,
			user: {
				id: user._id,
				username: user.username,
				himeNumber: user.himeNumber,
			},
		});
	} catch (error) {
		return handleError(res, error, 'Error during anonymous login');
	}
};

// Account Lockout After Failed Attempts
exports.checkLockout = async (req, res, next) => {
	const { email } = req.body;
	const user = await User.findOne({ email });
	if (!user) return res.status(404).json({ message: 'User not found' });

	if (user.failedAttempts >= MAX_FAILED_ATTEMPTS) {
		const lockExpiration = new Date(user.lockUntil);
		if (lockExpiration > new Date()) {
			return res
				.status(403)
				.json({ message: 'Account is locked. Try again later.' });
		}
		user.failedAttempts = 0;
		await user.save();
	}

	req.user = user;
	next();
};

exports.recordFailedAttempt = async (user) => {
	user.failedAttempts += 1;
	if (user.failedAttempts >= MAX_FAILED_ATTEMPTS) {
		user.lockUntil = new Date(Date.now() + LOCK_TIME);
	}
	await user.save();
};

// Upgrade anonymous user to Normal user
exports.upgradeAnonymousUser = async (req, res) => {
	try {
		const {
			himeNumber,
			email,
			password,
			username,
			bio,
			gender,
			dateOfBirth,
			phone,
			country,
			state,
			city,
			zipCode,
			language,
			theme,
			avatarUrl,
		} = req.body;

		const user = await User.findOne({ himeNumber });

		if (!user) {
			return res.status(404).json({ message: 'User not found' });
		}
		if (user.userType !== 'anonymous') {
			return res.status(400).json({
				message: 'User must be anonymous to change to a normal user.',
			});
		}

		const emailInUse = await User.findOne({ email });
		if (emailInUse) {
			return res.status(400).json({ message: 'Email is already in use.' });
		}

		const usernameInUse = await User.findOne({ username });
		if (usernameInUse) {
			return res.status(400).json({ message: 'Username is already in use.' });
		}

		const hashedPassword = await bcrypt.hash(password, 10);

		user.email = email;
		user.username = username;
		user.password = hashedPassword;
		user.userType = 'normal';
		user.bio = bio;
		user.gender = gender;
		user.dateOfBirth = dateOfBirth;
		user.phone = phone;
		user.address = {
			country,
			state,
			city,
			zipCode,
		};
		user.preferences = {
			language: language || 'en',
			theme: theme || 'light',
		};
		user.avatarUrl = avatarUrl;
		user.emailVerified = false;

		await user.save();

		await sendVerificationEmail(user, 'otp');

		res.status(200).json({
			message:
				'Anonymous user upgraded successfully. Please verify your email with the OTP sent.',
			user: generateUserResponse(user),
		});
	} catch (error) {
		return handleError(res, error, 'Error upgrading anonymous user');
	}
};
