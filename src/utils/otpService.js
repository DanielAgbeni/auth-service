const crypto = require('crypto');
const OTP = require('../models/OTP'); // OTP model for storing OTPs in the database

// Generate OTP
const generateOTP = (length = 6) => {
	const otp = crypto.randomInt(10 ** (length - 1), 10 ** length).toString();
	return otp;
};

// Save OTP to Database
const saveOTP = async (userId, otp, expiresIn = 5) => {
	const expiryTime = new Date(Date.now() + expiresIn * 60 * 1000); // Expiry in minutes
	const otpRecord = new OTP({
		userId,
		otp,
		expiresAt: expiryTime,
	});
	await otpRecord.save();
};

// Verify OTP
const verifyOTP = async (userId, otp) => {
	const otpRecord = await OTP.findOne({ userId, otp });
	if (!otpRecord) {
		throw new Error('Invalid OTP');
	}
	if (new Date() > otpRecord.expiresAt) {
		throw new Error('OTP has expired');
	}
	// OTP is valid; delete it
	await OTP.deleteOne({ _id: otpRecord._id });
	return true;
};

// Export functions
module.exports = {
	generateOTP,
	saveOTP,
	verifyOTP,
};
