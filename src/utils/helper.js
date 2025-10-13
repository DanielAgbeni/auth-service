const User = require('../models/User');
const Token = require('../models/token');
const generateHimeNumber = require('../services/himeNumberService');
const { generateToken } = require('./jwt');
const { generateOTP, saveOTP } = require('./otpService');
const bcrypt = require('bcryptjs');
const sendEmail = require('./emailService');

const handleError = (
	res,
	error,
	message = 'Internal Server Error',
	status = 500,
) => {
	console.error(message, error);
	return res.status(status).json({ message, error: error.message });
};

// Helper to generate user response
const generateUserResponse = (user) => ({
	id: user._id,
	username: user.username,
	email: user.email,
	himeNumber: user.himeNumber,
	userType: user.userType,
});

const findUserByIdentifier = async (identifier) => {
	return await User.findOne({
		$or: [
			{ email: identifier },
			{ username: identifier },
			{ himeNumber: identifier },
		],
	});
};
// Helper function to create a token
const createToken = async (userId, userAgent) => {
	const token = generateToken({ id: userId });
	const tokenDocument = new Token({
		userId: userId,
		token: token,
		isValid: true,
		expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours from now
		device: userAgent || 'unknown',
	});
	await tokenDocument.save();
	return token;
};

// Helper function to send a verification email
const sendVerificationEmail = async (
	user,
	verificationMethod,
	token = null,
) => {
	if (verificationMethod === 'otp') {
		const otp = generateOTP();
		await saveOTP(user._id, otp);

		const message = `
				<!DOCTYPE html>
				<html>
				<body>
				<p>Hi ${user.username},</p>
				<p>Thank you for signing up with us! To verify your email address, please use the following One-Time Passcode (OTP):</p>
				<p style="font-weight: bold; font-size: 16px;">${otp}</p>
				<p>This code is valid for 5 minutes.</p>
				</body>
				</html>
				`;

		await sendEmail(user.email, 'Email Verification OTP', message);
	} else if (verificationMethod === 'token') {
		const verificationUrl = `${process.env.BASE_URL}/auth/${user._id}/verify/${token}`;
		await sendEmail(user.email, 'Verify Email', verificationUrl);
	}
};

// Helper function to handle registration logic
const handleRegistration = async (
	res,
	email,
	password,
	username,
	userType,
	socialLoginProvider,
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
	verificationMethodFinal,
	req,
) => {
	try {
		// Generate a unique Hime Number
		const himeNumber = generateHimeNumber(userType === 'normal' ? 1 : 2);

		// Check if the username already exists
		const existingUser = await User.findOne({ username });
		if (existingUser) {
			return res.status(400).json({ message: 'Username is already taken.' });
		}

		// Check if email is already in use for 'normal' users
		if (userType === 'normal' && email) {
			const emailInUse = await User.findOne({ email });
			if (emailInUse) {
				return res.status(400).json({ message: 'Email is already in use.' });
			}
		}

		// Hash password for 'normal' users
		const hashedPassword =
			userType === 'normal' ? await bcrypt.hash(password, 10) : undefined;

		// Create new user
		const user = new User({
			email: userType === 'normal' ? email : undefined,
			password: hashedPassword,
			username,
			himeNumber,
			userType,
			socialLoginProvider:
				userType !== 'normal' ? socialLoginProvider : undefined,
			bio,
			gender,
			dateOfBirth,
			phone,
			address: {
				country,
				state,
				city,
				zipCode,
			},
			preferences: {
				language: language || 'en',
				theme: theme || 'light',
			},
			avatarUrl,
			emailVerified: false, // User always needs verification
			isPremium: false, // Default premium status
			role: 'user', // Default role
		});

		await user.save();

		// Handle Verification Logic
		if (verificationMethodFinal === 'otp' || userType === 'normal') {
			const token = await createToken(user._id, req.headers['user-agent']);

			await sendVerificationEmail(user, verificationMethodFinal, token);

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

		// For "none", registration is complete immediately
		return res.status(201).json({
			message: 'User registered successfully.',
			user: {
				username: user.username,
				himeNumber: user.himeNumber,
				userType: user.userType,
			},
		});
	} catch (error) {
		console.error('Error during user registration:', error);
		return res.status(500).json({
			message: 'Internal Server Error',
			error: error.message,
		});
	}
};
module.exports = {
	generateUserResponse,
	handleError,
	createToken,
	sendVerificationEmail,
	createToken,
	findUserByIdentifier,
	handleRegistration,
};
