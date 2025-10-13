// src/services/cleanupService.js
const User = require('../models/User');

const cleanupUnverifiedAccounts = async () => {
	try {
		// Find and delete unverified normal accounts that are older than 24 hours
		const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

		const result = await User.deleteMany({
			userType: 'normal',
			emailVerified: false,
			createdAt: { $lt: twentyFourHoursAgo },
		});

		console.log(`Cleaned up ${result.deletedCount} unverified accounts`);
	} catch (error) {
		console.error('Error in cleanup service:', error);
	}
};

module.exports = { cleanupUnverifiedAccounts };
