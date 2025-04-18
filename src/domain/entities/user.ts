export interface User {
  userId: string;
  email: string;
  password: string;
  role: string;
  createdAt?: Date;
  updatedAt?: Date;
} 