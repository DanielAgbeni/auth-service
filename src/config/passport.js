const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/userModel');

passport.use(
	new GoogleStrategy(
		{
			clientID: process.env.GOOGLE_CLIENT_ID,
			clientSecret: process.env.GOOGLE_CLIENT_SECRET,
			callbackURL: `${process.env.BASE_URL}/auth/google/callback`,
		},
		async (accessToken, refreshToken, profile, done) => {
			try {
				let user = await User.findOne({ email: profile.emails[0].value });

				// Create new user if not found
				if (!user) {
					const himeNumber = generateHimeNumber('normal');
					user = await User.create({
						email: profile.emails[0].value,
						username: profile.displayName,
						himeNumber,
						isVerified: true,
					});
				}

				done(null, user);
			} catch (err) {
				done(err, null);
			}
		},
	),
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
	const user = await User.findById(id);
	done(null, user);
});
