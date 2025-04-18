# Authentication Service API Documentation

This document provides comprehensive information about the Authentication Service API endpoints, their request/response formats, and usage guidelines.

## Table of Contents

- [Overview](#overview)
- [Base URL](#base-url)
- [Authentication](#authentication)
- [Error Handling](#error-handling)
- [API Endpoints](#api-endpoints)
  - [User Authentication](#user-authentication)
  - [Driver Authentication](#driver-authentication)
  - [Token Management](#token-management)
  - [OTP Operations](#otp-operations)
  - [Social Authentication](#social-authentication)

## Overview

The Authentication Service provides APIs for user and driver registration, login, token management, OTP verification, and social authentication.

## Base URL

```
http://localhost:3001/auth
```

## Authentication

Most endpoints require authentication via JWT tokens. Include the token in the Authorization header:

```
Authorization: Bearer <your_token>
```

## Error Handling

All API responses follow a consistent format:

### Success Response

```json
{
  "success": true,
  "message": "Operation completed successfully",
  // Additional data specific to the endpoint
}
```

### Error Response

```json
{
  "success": false,
  "error": "Error message",
  "errorCode": "ERROR_CODE"
}
```

## API Endpoints

### User Authentication

#### Register User

Register a new user account.

- **URL:** `/register`
- **Method:** `POST`
- **Auth Required:** No
- **Request Body:**

```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "role": "user",
  "fullName": "John Doe",
  "phone": "+919876543210"
}
```

- **Success Response:**

```json
{
  "success": true,
  "message": "OTP sent to your email for verification",
  "token": "jwt_token",
  "user": {
    "email": "user@example.com",
    "role": "user",
    "fullName": "John Doe",
    "phone": "+919876543210",
    "userId": "USR-abc123"
  }
}
```

#### Login User

Login with email and password.

- **URL:** `/login`
- **Method:** `POST`
- **Auth Required:** No
- **Request Body:**

```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

- **Success Response:**

```json
{
  "success": true,
  "message": "Login successful",
  "token": "jwt_access_token",
  "refreshToken": "jwt_refresh_token",
  "user": {
    "userId": "USR-abc123",
    "email": "user@example.com",
    "role": "user",
    "fullName": "John Doe",
    "profileImage": "https://example.com/profile.jpg"
  }
}
```

#### Verify Password

Verify user's password.

- **URL:** `/verify-password`
- **Method:** `POST`
- **Auth Required:** Yes
- **Request Body:**

```json
{
  "userId": "USR-abc123",
  "password": "SecurePassword123!"
}
```

- **Success Response:**

```json
{
  "success": true
}
```

#### Update Password

Update user's password.

- **URL:** `/update-password`
- **Method:** `PUT`
- **Auth Required:** Yes
- **Request Body:**

```json
{
  "userId": "USR-abc123",
  "currentPassword": "CurrentPassword123!",
  "newPassword": "NewPassword123!"
}
```

- **Success Response:**

```json
{
  "success": true,
  "message": "Password updated successfully"
}
```

#### Delete User

Delete a user account.

- **URL:** `/users/:userId`
- **Method:** `DELETE`
- **Auth Required:** Yes
- **Success Response:**

```json
{
  "success": true,
  "message": "User deleted"
}
```

### Driver Authentication

#### Register Driver

Register a new driver account.

- **URL:** `/register-driver`
- **Method:** `POST`
- **Auth Required:** No
- **Request Body:**

```json
{
  "email": "driver@example.com",
  "role": "driver",
  "partnerId": "DRV-abc123"
}
```

- **Success Response:**

```json
{
  "success": true,
  "message": "Driver email registered successfully",
  "user": {
    "email": "driver@example.com",
    "role": "driver",
    "partnerId": "DRV-abc123"
  }
}
```

#### Update Driver Email

Update a driver's email.

- **URL:** `/drivers/:partnerId/email`
- **Method:** `PUT`
- **Auth Required:** Yes
- **Request Body:**

```json
{
  "email": "newemail@example.com"
}
```

- **Success Response:**

```json
{
  "success": true,
  "message": "Email updated successfully",
  "user": {
    "userId": "DRV-abc123",
    "email": "newemail@example.com",
    "role": "driver"
  }
}
```

### Token Management

#### Verify Token

Verify if a token is valid.

- **URL:** `/verify-token`
- **Method:** `POST`
- **Auth Required:** Yes (token in header)
- **Success Response:**

```json
{
  "success": true,
  "valid": true,
  "user": {
    "userId": "USR-abc123",
    "email": "user@example.com",
    "role": "user"
  }
}
```

#### Refresh Token

Get a new access token using a refresh token.

- **URL:** `/refresh-token`
- **Method:** `POST`
- **Auth Required:** No
- **Request Body:**

```json
{
  "refreshToken": "jwt_refresh_token"
}
```

- **Success Response:**

```json
{
  "success": true,
  "token": "new_jwt_access_token",
  "refreshToken": "new_jwt_refresh_token",
  "user": {
    "userId": "USR-abc123",
    "email": "user@example.com",
    "role": "user"
  }
}
```

#### Logout

Invalidate a user's refresh token.

- **URL:** `/logout`
- **Method:** `POST`
- **Auth Required:** Yes
- **Request Body:**

```json
{
  "userId": "USR-abc123"
}
```

- **Success Response:**

```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

#### Create Temporary Token

Create a temporary token for document uploads or other purposes.

- **URL:** `/temp-token`
- **Method:** `POST`
- **Auth Required:** No
- **Request Body:**

For document upload:
```json
{
  "purpose": "document-upload",
  "role": "driver"
}
```

For normal token:
```json
{
  "userId": "USR-abc123",
  "email": "user@example.com",
  "role": "user"
}
```

- **Success Response:**

```json
{
  "success": true,
  "token": "jwt_token"
}
```

#### Verify Partner Token

Verify if a partner token is valid.

- **URL:** `/verify-partner-token`
- **Method:** `POST`
- **Auth Required:** Yes (token in header)
- **Request Body:**

```json
{
  "email": "driver@example.com"
}
```

- **Success Response:**

```json
{
  "success": true,
  "message": "Token is valid"
}
```

### OTP Operations

#### Send OTP

Send an OTP to the user's email.

- **URL:** `/send-otp`
- **Method:** `POST`
- **Auth Required:** No
- **Request Body:**

```json
{
  "email": "user@example.com"
}
```

- **Success Response:**

```json
{
  "success": true,
  "message": "OTP sent successfully"
}
```

#### Verify OTP

Verify an OTP sent to the user's email.

- **URL:** `/verify-otp`
- **Method:** `POST`
- **Auth Required:** No
- **Request Body:**

```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

For password reset:
```json
{
  "email": "user@example.com",
  "otp": "123456",
  "newPassword": "NewPassword123!"
}
```

- **Success Response:**

```json
{
  "success": true,
  "message": "OTP verified successfully",
  "token": "jwt_token",
  "refreshToken": "jwt_refresh_token"
}
```

#### Forgot Password

Initiate the password reset process by sending OTP.

- **URL:** `/forgot-password`
- **Method:** `POST`
- **Auth Required:** No
- **Request Body:**

```json
{
  "email": "user@example.com"
}
```

- **Success Response:**

```json
{
  "success": true,
  "message": "OTP sent successfully",
  "token": "temporary_token"
}
```

#### Request Login OTP

Request an OTP for driver login.

- **URL:** `/request-login-otp`
- **Method:** `POST`
- **Auth Required:** No
- **Request Body:**

```json
{
  "email": "driver@example.com"
}
```

- **Success Response:**

```json
{
  "success": true,
  "message": "OTP sent to your email for login"
}
```

#### Verify Login OTP

Verify OTP for driver login.

- **URL:** `/verify-login-otp`
- **Method:** `POST`
- **Auth Required:** No
- **Request Body:**

```json
{
  "email": "driver@example.com",
  "otp": "123456"
}
```

- **Success Response:**

```json
{
  "success": true,
  "message": "OTP verified successfully",
  "token": "jwt_token",
  "refreshToken": "jwt_refresh_token",
  "partnerId": "DRV-abc123",
  "email": "driver@example.com",
  "role": "driver"
}
```

### Social Authentication

#### Google Login

Authenticate using Google credentials.

- **URL:** `/google-login`
- **Method:** `POST`
- **Auth Required:** No
- **Request Body:**

```json
{
  "credential": "google_id_token"
}
```

- **Success Response:**

```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "userId": "USR-abc123",
    "email": "user@gmail.com",
    "role": "user",
    "fullName": "John Doe",
    "profileImage": "https://example.com/profile.jpg"
  },
  "token": "jwt_token",
  "refreshToken": "jwt_refresh_token"
}
```

## Status Codes

- `200 OK`: The request was successful
- `201 Created`: The resource was successfully created
- `400 Bad Request`: The request was invalid
- `401 Unauthorized`: Authentication failed
- `403 Forbidden`: The user does not have permission
- `404 Not Found`: The requested resource was not found
- `500 Internal Server Error`: An error occurred on the server

## Error Codes

- `REFRESH_TOKEN_MISSING`: Refresh token not provided
- `REFRESH_TOKEN_INVALID`: Refresh token is invalid
- `REFRESH_TOKEN_EXPIRED`: Refresh token has expired
- `REFRESH_TOKEN_MISMATCH`: Refresh token does not match stored token
- `USER_NOT_FOUND`: User not found
- `SERVER_ERROR`: Internal server error
- `PASSWORD_ERROR`: Password-related error
- `VALIDATION_ERROR`: Invalid input data
- `EMAIL_EXISTS`: Email already exists
- `UNAUTHORIZED`: User is not authorized
- `ACCOUNT_BLOCKED`: User account is blocked
- `INVALID_OTP`: OTP is invalid or expired 