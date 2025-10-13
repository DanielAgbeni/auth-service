const refreshMiddleware = async (req, res, next) => {
	const refreshToken = req.cookies?.refresh_token;

	if (!refreshToken) {
		return res.status(401).json({ message: 'No refresh token provided' });
	}

	try {
		const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
		const newToken = jwt.sign({ id: decoded.id }, process.env.JWT_SECRET, {
			expiresIn: '15m',
		});

		res.json({ success: true, token: newToken });
	} catch (err) {
		res.status(401).json({ message: 'Invalid refresh token' });
	}
};

module.exports = refreshMiddleware;
