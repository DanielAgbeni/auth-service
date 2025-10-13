# HiMe Auth Service

The HiMe Auth Service manages user registration and authentication, supporting traditional, social media, and anonymous login options with unique HiMe Numbers for user identification.

## Features

- **Traditional Registration:** Email, username, password, with OTP verification
- **Social Media Login:** Google OAuth integration
- **Anonymous Access:** Anonymous registration with limited profile customization
- **HiMe Number Generation:** Unique identifiers for users
- **Account Management:** Profile updates, account deactivation/deletion
- **Security Features:** Session management, account lockout protection
- **Email Verification:** OTP verification and email validation

## Setup

1. Clone the repository
2. Install dependencies: `npm install`
3. Configure environment variables in `.env`:

   ```plaintext
   PORT=3001
   JWT_SECRET=your_jwt_secret
   JWT_EXPIRY=1h
   MONGO_URI=your_mongo_uri
   ```

4. Start the service:
   - Development: `npm run dev`
   - Production: `npm start`

## API Endpoints

### Public Routes

| Method | Endpoint                | Description                    |
|--------|------------------------|--------------------------------|
| POST   | `/auth/register`       | Register traditional user      |
| POST   | `/auth/login`          | Login with credentials         |
| POST   | `/auth/anonymous-register` | Register anonymous user    |
| POST   | `/auth/anonymous-login`    | Login as anonymous user    |
| POST   | `/auth/social-login`   | Login/register via social media|
| POST   | `/auth/password-recovery` | Initiate password recovery  |
| POST   | `/auth/resetpassword`  | Reset password                 |

### Email Verification Routes

| Method | Endpoint                | Description                    |
|--------|------------------------|--------------------------------|
| POST   | `/auth/resend-verification` | Resend verification email |
| POST   | `/auth/verify-email`   | Verify email address           |

### Protected Routes (Require Authentication)

| Method | Endpoint                | Description                    |
|--------|------------------------|--------------------------------|
| PUT    | `/auth/profile`        | Update user profile            |
| POST   | `/auth/logout`         | Logout user                    |
| POST   | `/auth/invalidate-sessions` | Invalidate other sessions |
| POST   | `/auth/whitelist`      | Add to whitelist              |
| PUT    | `/auth/contact-info`   | Update contact information     |
| GET    | `/auth/users`          | Get all users                  |
| POST   | `/auth/deactivate`     | Deactivate account            |
| DELETE | `/auth/delete`         | Delete account                 |

## Dependencies

- Express.js - Web framework
- MongoDB/Mongoose - Database
- JWT - Authentication
- Bcrypt - Password hashing
- Nodemailer - Email services
- Passport - OAuth authentication
- Other utilities: cors, dotenv, validator

## Development

Run the service in development mode:

```bash
npm run dev
```

This will start the service with nodemon for automatic reloading during development.
