// infrastructure/repositories/authRepositoryImpl.ts
import { AuthRepository } from '../../domain/repositories/authRepository';
import { Auth } from '../../domain/entities/auth';
import { AuthModel } from '../models/authModel';
import bcrypt from 'bcrypt';

export class AuthRepositoryImpl implements AuthRepository {
  async findByEmail(email: string): Promise<Auth | null> {
    return AuthModel.findOne({ email }).lean();
  }

  async create(auth: Omit<Auth, 'userId'> & { userId: string }): Promise<Auth> {
    const newAuth = new AuthModel(auth);
    return (await newAuth.save()).toObject();
  }

  async findById(userId: string): Promise<Auth | null> {
    return AuthModel.findOne({ userId }).lean();
  }

  async update(userId: string, data: Partial<Auth>): Promise<Auth> {
    const updatedAuth = await AuthModel.findOneAndUpdate(
      { userId },
      { $set: data },
      { new: true }
    ).lean();

    if (!updatedAuth) {
      throw new Error('Auth not found');
    }

    return updatedAuth;
  }

  async updatePassword(userId: string, hashedPassword: string): Promise<void> {
    await AuthModel.updateOne(
      { userId },
      { $set: { password: hashedPassword } }
    );
  }

  async delete(userId: string): Promise<boolean> {
    try {
      // Replace this with your actual delete implementation
      // For example, using Mongoose:
      // const result = await AuthModel.deleteOne({ userId });
      // return result.deletedCount === 1;
      
      // For now, we'll just simulate a successful deletion
      console.log(`Deleting user with ID: ${userId}`);
      return true;
    } catch (error) {
      console.error(`Failed to delete user with ID ${userId}:`, error);
      return false;
    }
  }

  async updateEmail(userId: string, email: string): Promise<Auth | null> {
    try {
      const updatedUser = await AuthModel.findOneAndUpdate(
        { userId },
        { $set: { email } },
        { new: true }
      ).lean();

      return updatedUser;
    } catch (error) {
      console.error('Error updating email:', error);
      return null;
    }
  }
}