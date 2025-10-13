const { generateOTP, saveOTP, verifyOTP } = require('../utils/otpService');
const User = require('../models/User');
const sendEmail = require('../utils/emailService');

// Send OTP to a user
exports.sendOTP = async (req, res) => {
	try {
		const { userId } = req.body;
		const user = await User.findById(userId);
		if (!user) {
			return res.status(404).json({ message: 'User not found' });
		}

		const otp = generateOTP();
		await saveOTP(userId, otp);
		// Simulate sending OTP (e.g., via SMS or email)
		console.log(`OTP for user ${user.username}: ${otp}`);
		await sendEmail(
			user.email,
			'Verify OTP',
			`OTP for user ${user.username}: ${otp}`,
		);

		res.status(200).json({ message: 'OTP sent successfully' });
	} catch (err) {
		res.status(500).json({ message: 'Server error', error: err.message });
	}
};

// Verify OTP
exports.verifyOTP = async (req, res) => {
	try {
		const { userId, otp } = req.body;
		await verifyOTP(userId, otp);
		await User.findByIdAndUpdate(userId, { emailVerified: true });
		res.status(200).json({ message: 'OTP verified successfully' });
	} catch (err) {
		res
			.status(400)
			.json({ message: 'Verification failed', error: err.message });
	}
};
