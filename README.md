# Auth Package: `mongoauth`

## Overview

The `mongoauth` package provides a prebuilt authentication solution using MongoDB and Express. It offers essential authentication features, such as user registration, login, password reset, profile updates, and email verification, while leveraging MongoDB for user data storage. This package is designed to streamline the process of adding authentication to your Node.js application.

---

## Features

- **User Registration**: Register users with email and password validation.
- **Login**: Authenticate users with JWT-based session management.
- **Email Verification**: Ensure user accounts are valid by sending a verification email.
- **Forgot Password**: Allow users to reset their passwords via email.
- **Change Password**: Enable users to securely update their passwords.
- **Profile Management**: Allow users to update their profiles.
- **Domain Restriction**: Restrict signups to specific email domains.

---

## Installation

```bash

npm install mongoauth

```

# Usage

Here's how you can set up and use the backend authentication package in your project:

## Step 1: Import and Configure the Package

```javascript
const express = require('express');
const mongoose = require('mongoose');
const { createAuthRouter } = require('backend');
require('dotenv').config();

const app = express();
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_CONNECTION_STRING)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Configure the package
const config = {
  jwtSecret: process.env.JWT_SECRET,
  mongoUrl: process.env.MONGO_CONNECTION_STRING,
  emailService: {
    email: process.env.EMAIL,
    password: process.env.PASSWORD,
  },
  frontendUrl: 'http://localhost:3000', // Frontend URL for redirects
  validDomains: new Map([
    ['gmail.com', 'gm'],
  ]),
};

// Create the auth router
const authRouter = createAuthRouter(config);
app.use('/api/user', authRouter);
```

## Step 2: Set Up Environment Variables

Create a `.env` file in your project root and include the following variables:

```
MONGO_CONNECTION_STRING=<Your MongoDB connection string>
JWT_SECRET=<Your JWT secret>
EMAIL=<Your email address>
PASSWORD=<Your email password>
```

## Endpoints

### User Authentication

### Get Current User

**GET** `/api/user/`

**Request Headers:**

```json
{
    "Authorization": "Bearer <token>"
}

```

#### Register a New User

**POST** `/api/user/signup`

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:** Registration success message with email verification link.

#### Login

**POST** `/api/user/login`

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:** JWT token for session management.

#### Email Verification

**GET** `/api/user/verify_email/:token`

Verifies the user's email using the token.

### Password Management

#### Forgot Password

**POST** `/api/user/forget_password`

**Request Body:**

```json
{
  "email": "user@example.com"
}
```

**Request Headers:**

```json
{
    "Authorization": "Bearer <token>"
}

```


**Response:** Password reset link sent to the user's email.

#### Reset Password

**POST** `/api/user/reset_password/:token`

**Request Body:**

```json
{
  "newPassword": "newpassword123"
}
```

#### Change Password

**POST** `/api/user/change_password`

**Request Body:**

```json
{
  "currentPassword": "password123",
  "newPassword": "newpassword123"
}
```

**Request Headers:**

```json
{
    "Authorization": "Bearer <token>"
}

```

### Profile Management

#### Update Profile

**PATCH** `/api/user/update_user_profile`

**Request Body:**

```json
{
  "name": "New Name",
  "bio": "Updated bio"
}
```


**Request Headers:**

```json
{
    "Authorization": "Bearer <token>"
}

```

## Configuration Options

The `config` object requires the following:

| Key           | Type   | Description                                     |
|---------------|--------|-------------------------------------------------|
| `jwtSecret`   | string | Secret key for signing JWT tokens.             |
| `mongoUrl`    | string | MongoDB connection string.                     |
| `emailService`| object | Object containing email and password for email service. |
| `frontendUrl` | string | URL of your frontend application.              |
| `validDomains`| Map    | Map of allowed email domains and their labels. |


