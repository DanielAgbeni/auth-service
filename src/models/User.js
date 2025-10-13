const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
	// Basic Details
	email: {
		type: String,
		sparse: true,
		lowercase: true,
		trim: true,
	},
	username: {
		type: String,
		unique: true,
		required: true,
		trim: true,
	},
	password: { type: String },
	himeNumber: {
		type: String,
		unique: true,
		required: true,
	},
	userType: {
		type: String,
		enum: ['normal', 'anonymous'],
		required: true,
	},

	// Social Login
	socialLoginProvider: { type: String },
	providerId: { type: String }, // Added for social login tracking

	// Profile Info
	avatarUrl: { type: String },
	bio: { type: String },
	gender: {
		type: String,
		enum: ['male', 'female', 'other'],
		default: 'other',
	},
	dateOfBirth: { type: Date },
	phone: { type: String, sparse: true },
	address: {
		country: { type: String },
		state: { type: String },
		city: { type: String },
		zipCode: { type: String },
	},

	// Security Features
	emailVerified: { type: Boolean, default: false },
	isActive: { type: Boolean, default: true },
	failedAttempts: {
		type: Number,
		default: 0,
		max: 5,
	},
	lockUntil: { type: Date },
	whitelist: {
		type: [String],
		default: [],
	},
	role: {
		type: String,
		enum: ['user', 'admin', 'moderator'],
		default: 'user',
	},

	// Account Deactivation Tracking
	deactivatedAt: { type: Date },
	lastActive: { type: Date },

	// Preferences and Settings
	preferences: {
		language: { type: String, default: 'en' },
		theme: { type: String, enum: ['light', 'dark'], default: 'light' },
	},

	// HiMe Features
	isVerified: { type: Boolean, default: false },
	isPremium: { type: Boolean, default: false },
	premiumDetails: {
		startDate: { type: Date },
		endDate: { type: Date },
		plan: { type: String },
	},
	// Audit and Login Tracking
	createdAt: { type: Date, default: Date.now },
	updatedAt: { type: Date, default: Date.now },
	lastLogin: { type: Date },
});

// Middleware to update `updatedAt` before save
userSchema.pre('save', function (next) {
	this.updatedAt = Date.now();
	next();
});

// Virtual to check if account is locked
userSchema.virtual('isLocked').get(function () {
	return this.lockUntil && this.lockUntil > Date.now();
});

// Method to reset failed attempts
userSchema.methods.resetFailedAttempts = function () {
	this.failedAttempts = 0;
	this.lockUntil = undefined;
	return this.save();
};

module.exports = mongoose.model('User', userSchema);
