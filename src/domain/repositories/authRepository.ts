import { Auth } from '../entities/auth';

export interface AuthRepository {
  create(user: { userId: string; email: string; password: string; role: string }): Promise<any>;
  findByEmail(email: string): Promise<any | null>;
  findById(userId: string): Promise<any | null>;
  update(userId: string, data: any): Promise<any>;
  updatePassword(userId: string, newPassword: string): Promise<any>;
  updateEmail(userId: string, newEmail: string): Promise<any>;
  delete(userId: string): Promise<boolean>;
}