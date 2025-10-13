// src/middlewares/authMiddleware.js
const jwt = require('jsonwebtoken');
const { jwtSecret } = require('../config/config');
const Token = require('../models/token');

const authMiddleware = async (req, res, next) => {
	try {
		const authHeader = req.headers.authorization;
		// console.log('Auth Header:', authHeader); // Debug log

		if (!authHeader || !authHeader.startsWith('Bearer ')) {
			return res.status(401).json({
				message: 'Authorization token missing or invalid format',
			});
		}

		const token = authHeader.split(' ')[1];
		// console.log('Token being verified:', token); // Debug log

		// Find token in database
		const tokenDoc = await Token.findOne({
			token,
			isValid: true,
			expiresAt: { $gt: new Date() },
		});

		// console.log('Token document found:', tokenDoc); // Debug log

		if (!tokenDoc) {
			return res.status(401).json({
				message: 'Token not found in database or expired',
				details: 'Please login again to get a new token',
			});
		}

		// Verify JWT
		const decoded = jwt.verify(token, jwtSecret);
		// console.log('Decoded token:', decoded); // Debug log

		req.user = decoded;

		// Update last used timestamp
		tokenDoc.lastUsed = new Date();
		await tokenDoc.save();

		next();
	} catch (error) {
		console.error('Auth Middleware Error:', error);
		return res.status(401).json({
			message: 'Token verification failed',
			details:
				process.env.NODE_ENV === 'development'
					? error.message
					: 'Invalid token',
		});
	}
};

module.exports = authMiddleware;
