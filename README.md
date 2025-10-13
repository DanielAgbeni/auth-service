# HiMe Auth Service

Auth-service provides user registration, authentication, session management, email/OTP verification, social (Google) login, anonymous accounts, and account management for the HiMe Chat platform.

This README documents the available HTTP endpoints and the environment variables required to run the service.

## Quick start

1. Clone the repository
2. Install dependencies:

```bash
npm install
```

3. Create a `.env` file (see `.env.example` section below)

4. Start the service:

```bash
npm run dev    # development (nodemon)
npm start      # production
```

By default the server listens on `PORT` (see `.env`). Routes are mounted under `/auth` and `/otp` as documented below.

## Base route prefixes

- Auth routes: `/auth`
- OTP routes: `/otp`

All protected routes require an Authorization header with a valid bearer token:

Authorization: Bearer <token>

Some endpoints also accept or return a `token` in the request/response body (e.g. reset tokens) — read each endpoint notes.

## Endpoints

Note: All routes below are mounted with the `/auth` or `/otp` prefix from `app.js`.

Auth routes (`/auth`)

- POST /auth/register
  - Description: Register a new user (normal or anonymous). Body accepts fields like `email`, `username`, `password`, `userType` ("normal" or "anonymous"), plus profile fields. For normal users email/password are required.
  - Public

- POST /auth/login
  - Description: Login with `email` or `username` or `himeNumber` and `password`.
  - Public (rate/lockout protections apply)

- POST /auth/anonymous-register
  - Description: Create an anonymous account (username + password).
  - Public

- POST /auth/anonymous-login
  - Description: Login as an anonymous user (username or himeNumber + password).
  - Public

- POST /auth/social-login
  - Description: Social login (currently Google). Body: `{ token, provider: 'google' }`.
  - Public

- POST /auth/password-recovery
  - Description: Generate & send password reset OTP to the user email. Body: `{ email }`.
  - Public

- POST /auth/verifyresetotp
  - Description: Verify the OTP sent for password recovery. Body: `{ email, otp }`.
  - Public — returns a short-lived reset token on success.

- POST /auth/resetpassword
  - Description: Reset the password using the reset token. Body: `{ token, newPassword }`.
  - Public (token-based)

- POST /auth/resend-verification
  - Description: Resend email verification. Body: `{ email, method }` where method is `otp` or `token`.
  - Public

- POST /auth/verify-email
  - Description: Verify email using `userId` and `token` (token method) or OTP method when applicable. Body: `{ userId, token }` or OTP flow.
  - Public

Protected routes (require Authorization: Bearer <token>)

- PUT /auth/updateprofile
  - Description: Update profile fields (username, email, password, address, preferences, avatarUrl).

- POST /auth/logout
  - Description: Logout; body expects `{ token }` (the token to invalidate) or you can rely on client to drop token.

- POST /auth/invalidate-sessions
  - Description: Invalidate other sessions for the current authenticated user.

- POST /auth/whitelist
  - Description: Add deviceId or IP to user's whitelist. Body: `{ deviceId, ip }`.

- PUT /auth/update-contact-info
  - Description: Update user `email` or `phone`.

- GET /auth/users
  - Description: Admin-only endpoint to list users with pagination and filters. Query params: `page`, `limit`, `userType`, `searchQuery`, `sortBy`, `sortOrder`.

- POST /auth/deactivate
  - Description: Deactivate the authenticated user's account.

- DELETE /auth/delete
  - Description: Delete the authenticated user's account.

- POST /auth/switch-usertype
  - Description: Upgrade anonymous user to normal user. Body: includes `himeNumber`, `email`, `password`, etc.

OTP routes (`/otp`)

- POST /otp/send
  - Description: Send OTP to user. Body: `{ userId }`.

- POST /otp/verify
  - Description: Verify OTP. Body: `{ userId, otp }`.

Other

- Google OAuth callback: the Passport config expects the callback to be at `${BASE_URL}/auth/google/callback`. If you wire frontend redirects to Google OAuth, ensure `BASE_URL` matches your deployed host.

## Authorization and tokens

- The service issues JWTs and also persists token documents in the database (`Token` model). For protected routes include:

   Authorization: Bearer <JWT>

- Some flows use short-lived tokens saved in the `Token` collection (for password reset, email verification using token). Those tokens are passed in request bodies where needed.

## Environment variables (.env)

Below are the environment variables referenced throughout the code. Marked Required vs Optional and example values.

Required

- MONGO_URI: MongoDB connection string (e.g. mongodb+srv://.../dbname)
- JWT_SECRET: Secret string used to sign JWTs
- EMAIL_USER: Mail account (sender) used by nodemailer (e.g. <devdotdis@gmail.com>)
- EMAIL_PASS: Password or app password for the mail account
- BASE_URL: Public base URL of this service (used for verification links), e.g. <https://himechatauth.vercel.app>

Recommended / Optional

- PORT: Port to run the server (default 5000)
- JWT_EXPIRY: Optional override for token expiry (code reads this but default sign uses 1h)
- FIREBASE_DATABASE_URL: If using Firebase (optional)
- GOOGLE_CLIENT_ID: Google OAuth client id (for social login)
- GOOGLE_CLIENT_SECRET: Google OAuth client secret
- EMAIL_PORT: SMTP port (587 or 465)
- SECURE: boolean for secure SMTP (true for 465)
- SERVICE / HOST: SMTP service/host (gmail / smtp.gmail.com)
- NODE_ENV: development | production (affects some error messages)

Minimal `.env` example

```env
PORT=5000
MONGO_URI=your_mongo_connection_string
JWT_SECRET=replace_with_a_strong_secret
BASE_URL=http://localhost:5000
EMAIL_USER=youremail@example.com
EMAIL_PASS=your_email_password_or_app_password
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

Notes about email setup

- The repository uses `nodemailer` with Gmail by default. For production use either a proper SMTP provider or create an App Password for Gmail (if using Google accounts with 2FA).
- The code contains transports that sometimes use port 465 (secure true) and example .env had 587; pick the correct combination for your SMTP provider.

## Where the routes are defined

- `src/routes/authRoutes.js` — main auth endpoints mounted at `/auth`
- `src/routes/otpRoutes.js` — OTP endpoints mounted at `/otp`

## How to test

- Use a REST client (Postman / Insomnia) or curl. For protected routes first call `/auth/login` to obtain a token and include it in the `Authorization` header for subsequent requests.

## Files of interest

- `app.js` — server bootstrap and route mounting
- `src/config/db.js` — MongoDB connection (uses `MONGO_URI`)
- `src/config/passport.js` — Google OAuth configuration (uses `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `BASE_URL`)
- `src/utils/emailService.js` — email sender (uses `EMAIL_USER`, `EMAIL_PASS`)

If you want, I can also add a small `env.example` file to the repo with the minimal required keys — tell me if you'd like that created and I will add it.
