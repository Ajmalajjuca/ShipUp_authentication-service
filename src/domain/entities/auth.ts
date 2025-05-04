export interface Auth {
  userId: string;
  email: string;
  password: string;
  role: 'user' | 'partner' | 'admin';
  refreshToken?: string;
  refreshTokenExpiry?: Date;
  createdAt?: Date;
  updatedAt?: Date;
}