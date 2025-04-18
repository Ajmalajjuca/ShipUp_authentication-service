// src/application/services/otpService.ts
import { randomInt } from 'crypto';
import bcrypt from 'bcrypt';
import { RedisClientType, createClient } from 'redis';
import { Auth } from '../../domain/entities/auth';

export interface OtpServiceInterface {
  generateOtp(): string;
  storeOtp(email: string, otp: string): Promise<void>;
  verifyOtp(email: string, otp: string): Promise<{ isValid: boolean; user?: Auth }>;
  clearOtp(email: string): Promise<void>;
  
  // Add redis client access methods
  setRedisKey(key: string, value: string, expirationSeconds?: number): Promise<void>;
  getRedisKey(key: string): Promise<string | null>;
  deleteRedisKey(key: string): Promise<void>;
}

export class OtpService implements OtpServiceInterface {
  private redisClient: RedisClientType;
  private readonly OTP_EXPIRATION_SECONDS = 60; 

  constructor() {
    this.redisClient = createClient({ url: process.env.REDIS_URL });

    this.redisClient.connect()
      .then(() => console.log('Connected to Redis'))
      .catch((err: any) => console.error('Redis connection failed:', err));
  }

  generateOtp(): string {
    return randomInt(100000, 999999).toString();
  }

  async storeOtp(email: string, otp: string): Promise<void> {
    try {
      const hashedOtp = await bcrypt.hash(otp, 10); // Secure OTP storage

      // Store OTP and user in Redis with the same expiration
      await this.redisClient.setEx(`${email}:otp`, this.OTP_EXPIRATION_SECONDS, hashedOtp);

      console.log(`OTP for ${email}: ${otp}`); // Simulate email sending
    } catch (error) {
      console.error(`Error storing OTP and user for ${email}:`, error);
      throw error; // Re-throw to handle in caller
    }
  }

  async verifyOtp(email: string, enteredOtp: string): Promise<{ isValid: boolean; user?: Auth }> {
    try {
      const storedHashedOtp = await this.redisClient.get(`${email}:otp`);
      if (!storedHashedOtp) {
        return { isValid: false };
      }
      
      const isMatch = await bcrypt.compare(enteredOtp, storedHashedOtp);

      if (!isMatch) {
        return { isValid: false };
      }

      // OTP is valid and used, clear both OTP and user data
      await this.redisClient.del(`${email}:otp`);

      return { isValid: true };
    } catch (error) {
      console.error(`Error verifying OTP for ${email}:`, error);
      return { isValid: false };
    }
  }

  async clearOtp(email: string): Promise<void> {
    try {
      await this.redisClient.del(`${email}:otp`);
    } catch (error) {
      console.error('Error clearing OTP:', error);
    }
  }

  // Implement the Redis access methods
  async setRedisKey(key: string, value: string, expirationSeconds?: number): Promise<void> {
    try {
      if (expirationSeconds) {
        await this.redisClient.setEx(key, expirationSeconds, value);
      } else {
        await this.redisClient.set(key, value);
      }
    } catch (error) {
      console.error(`Error setting Redis key ${key}:`, error);
      throw error;
    }
  }

  async getRedisKey(key: string): Promise<string | null> {
    try {
      return await this.redisClient.get(key);
    } catch (error) {
      console.error(`Error getting Redis key ${key}:`, error);
      return null;
    }
  }

  async deleteRedisKey(key: string): Promise<void> {
    try {
      await this.redisClient.del(key);
    } catch (error) {
      console.error(`Error deleting Redis key ${key}:`, error);
    }
  }
}