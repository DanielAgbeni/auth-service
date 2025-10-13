const express = require('express');
const cors = require('cors'); // Add this line
// const mongoose = require('mongoose');
const connectDB = require('./src/config/db');
const authRoutes = require('./src/routes/authRoutes');
const otpRoutes = require('./src/routes/otpRoutes');
const app = express();
const { cleanupUnverifiedAccounts } = require('./src/services/cleanupService');

connectDB();

require('dotenv').config();

// Add CORS middleware
app.use(
	cors({
		origin: [
			'http://localhost:3000',
			'http://127.0.0.1:3000',
			'http://localhost:5500',
			'http://127.0.0.1:5500',
			'http://localhost:3001',
			'http://127.0.0.1:3001',
		],
		methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
		allowedHeaders: ['Content-Type', 'Authorization'],
	}),
);

app.use(express.json());
app.use('/auth', authRoutes);
app.use('/otp', otpRoutes);

app.use((err, req, res, next) => {
	console.error(err.stack);
	res
		.status(err.status || 500)
		.json({ message: err.message || 'Internal Server Error' });
});

// Run cleanup every 24 hours
const CLEANUP_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

// Initial cleanup
// cleanupUnverifiedAccounts();

// Schedule periodic cleanup
// setInterval(cleanupUnverifiedAccounts, CLEANUP_INTERVAL);

const PORT = process.env.PORT || 3010;
app.listen(PORT, () =>
	console.log(`Auth Service running on port http://localhost:${PORT}`),
);
