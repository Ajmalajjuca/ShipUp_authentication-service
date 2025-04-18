import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

declare global {
    namespace Express {
        interface Request {
            user?: any;
        }
    }
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        res.status(401).json({ error: 'Access denied. No token provided.' });
        return;
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        req.user = decoded;
        next();
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            res.status(401).json({ error: 'Token expired', tokenExpired: true });
            return;
        }
        res.status(403).json({ error: 'Invalid token.' });
        return;
    }
};

export const validateRefreshToken = (req: Request, res: Response, next: NextFunction): void => {
    const refreshToken = req.body.refreshToken;

    if (!refreshToken) {
        res.status(401).json({ error: 'Refresh token is required' });
        return;
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET || 'your-refresh-secret-key');
        req.user = decoded;
        next();
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            res.status(401).json({ error: 'Refresh token expired, please login again' });
            return;
        }
        res.status(403).json({ error: 'Invalid refresh token' });
        return;
    }
};