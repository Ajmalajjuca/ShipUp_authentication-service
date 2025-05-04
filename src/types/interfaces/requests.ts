export interface RegisterRequest {
  email: string;
  password: string;
  role: string;
  fullName: string;
  phone: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface OtpRequest {
  email: string;
}

export interface VerifyOtpRequest {
  email: string;
  otp: string;
  newPassword?: string;
}

export interface PasswordUpdateRequest {
  userId: string;
  currentPassword: string;
  newPassword: string;
}

export interface GoogleLoginRequest {
  credential: string;
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface LogoutRequest {
  userId: string;
}

export interface EmailUpdateRequest {
  email: string;
}

export interface TempTokenRequest {
  purpose?: string;
  role?: string;
  userId?: string;
  email?: string;
}

export interface DriverRegistrationRequest {
  email: string;
  role: string;
  partnerId: string;
}

export interface VerifyPasswordRequest {
  userId: string;
  password: string;
} 