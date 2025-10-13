const express = require('express');
const cors = require('cors');
const connectDB = require('./src/config/db');
const authRoutes = require('./src/routes/authRoutes');
const otpRoutes = require('./src/routes/otpRoutes');
const { cleanupUnverifiedAccounts } = require('./src/services/cleanupService');

require('dotenv').config();

const app = express();
connectDB();

// Allow all origins
app.use(
	cors({
		origin: '*',
		methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
		allowedHeaders: ['Content-Type', 'Authorization'],
	}),
);

app.use(express.json());
app.use('/auth', authRoutes);
app.use('/otp', otpRoutes);

// Global error handler
app.use((err, req, res, next) => {
	console.error(err.stack);
	res
		.status(err.status || 500)
		.json({ message: err.message || 'Internal Server Error' });
});

// Run cleanup every 24 hours
const CLEANUP_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours in ms
// cleanupUnverifiedAccounts();
// setInterval(cleanupUnverifiedAccounts, CLEANUP_INTERVAL);

const PORT = process.env.PORT || 3010;
app.listen(PORT, () =>
	console.log(`Auth Service running on http://localhost:${PORT}`),
);
