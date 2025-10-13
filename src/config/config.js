// src/config.js
require('dotenv').config();

module.exports = {
	port: process.env.PORT || 3001,
	jwtSecret: process.env.JWT_SECRET,
	jwtExpiry: process.env.JWT_EXPIRY,
	firebaseDatabaseUrl: process.env.FIREBASE_DATABASE_URL,
};
