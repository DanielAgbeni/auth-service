const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const tokenSchema = new Schema({
	userId: {
		type: Schema.Types.ObjectId,
		required: true,
		default: () => new mongoose.Types.ObjectId(), // Automatically generates a unique ObjectId
	},
	token: {
		type: String,
		required: true,
	},
	type: {
		type: String,
		enum: ['access', 'refresh', 'reset'],
		default: 'access',
	},
	device: {
		type: String,
		default: 'unknown',
	},
	lastUsed: {
		type: Date,
		default: Date.now,
	},
	expiresAt: {
		type: Date,
		required: true,
	},
	isValid: {
		type: Boolean,
		default: true,
	},
	createdAt: {
		type: Date,
		default: Date.now,
		expires: 86400 * 91, // Automatically delete documents after 3 months
	},
});

// Index for faster queries
tokenSchema.index({ userId: 1, token: 1 });
tokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('token', tokenSchema);
