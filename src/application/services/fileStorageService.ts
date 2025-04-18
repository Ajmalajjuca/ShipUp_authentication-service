export interface FileStorageService {
    uploadFile(directory: string, file: Express.Multer.File): Promise<string>;
  }