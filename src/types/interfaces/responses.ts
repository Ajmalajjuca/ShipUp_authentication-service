export interface BaseResponse {
  success: boolean;
  message?: string;
  error?: string;
  errorCode?: string;
}

export interface TokenResponse extends BaseResponse {
  token?: string;
  refreshToken?: string;
  partnerId?: string;
  email?: string;
  role?: string;
  user?: {
    userId: string;
    email: string;
    role: string;
    [key: string]: any; // Allow additional properties
  };
}

export interface UserResponse extends TokenResponse {
  user?: {
    userId: string;
    email: string;
    role: string;
    fullName?: string;
    phone?: string;
    profileImage?: string;
    status?: boolean;
  };
}

export interface OtpResponse extends BaseResponse {
  token?: string;
}

export interface VerifyTokenResponse extends BaseResponse {
  valid: boolean;
  message?: string;
  user?: {
    userId: string;
    email: string;
    role: string;
  };
}

export interface VerifyPasswordResponse extends BaseResponse {
  passwordError?: boolean;
}

export interface PartnerResponse extends TokenResponse {
  partnerId?: string;
  email?: string;
  role?: string;
}

export interface GoogleAuthResponse extends TokenResponse {
  user?: {
    userId: string;
    email: string;
    role: string;
    fullName?: string;
    profileImage?: string;
  };
}

export interface EmailUpdateResponse extends BaseResponse {
  user?: {
    userId: string;
    email: string;
    role: string;
  };
} 