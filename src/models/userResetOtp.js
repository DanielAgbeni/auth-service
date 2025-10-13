const mongoose = require('mongoose');

const userResetOTPSchema = new mongoose.Schema({
	userId: {
		type: mongoose.Schema.Types.ObjectId,
		ref: 'User',
		required: true,
	},
	email: {
		type: String,
		required: true,
	},
	otp: {
		type: String,
		required: true,
	},
	createdAt: {
		type: Date,
		default: Date.now,
		expires: 600, // Document expires after 10 minutes
	},
});

module.exports = mongoose.model('UserResetOTP', userResetOTPSchema);
