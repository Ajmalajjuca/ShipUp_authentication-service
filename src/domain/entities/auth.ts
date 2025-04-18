export interface Auth {
  userId: string;
  email: string;
  password: string;
  role: 'user' | 'driver' | 'admin';
  refreshToken?: string;
  refreshTokenExpiry?: Date;
  createdAt?: Date;
  updatedAt?: Date;
}