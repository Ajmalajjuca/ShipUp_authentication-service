import { FileStorageService } from './fileStorageService';
import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

export class FileStorageServiceImpl implements FileStorageService {
  private readonly baseUploadDir: string;

  constructor(baseUploadDir: string = 'uploads') {
    this.baseUploadDir = baseUploadDir;
    this.ensureDirectoryExists(this.baseUploadDir);
  }

  async uploadFile(directory: string, file: Express.Multer.File): Promise<string> {
    const fullDir = path.join(this.baseUploadDir, directory);
    this.ensureDirectoryExists(fullDir);

    const fileExtension = path.extname(file.originalname);
    const fileName = `${uuidv4()}${fileExtension}`;
    const filePath = path.join(fullDir, fileName);
    
    // Create a writable stream
    const writeStream = fs.createWriteStream(filePath);
    
    return new Promise((resolve, reject) => {
      writeStream.write(file.buffer);
      writeStream.end();
      
      writeStream.on('finish', () => {
        // Return the relative path that can be stored in the database
        resolve(path.join(directory, fileName));
      });
      
      writeStream.on('error', (err) => {
        reject(err);
      });
    });
  }

  private ensureDirectoryExists(directory: string): void {
    if (!fs.existsSync(directory)) {
      fs.mkdirSync(directory, { recursive: true });
    }
  }
}