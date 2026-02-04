import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';

// Define Types/Interfaces

export enum UserRole {
    ADMIN = 'ADMIN',
    STAFF = 'STAFF',
    VIEWER = 'VIEWER'
} 

export interface JWTPayload {
    id: string; // User ID
    email: string;
    role: UserRole;
    team_id?: string;
    iat: number;
    exp: number;
}

export interface AuthRequest extends Request {
    user?: JWTPayload | undefined;
    ip: string;
    userAgent: string;
}

export class PasswordService {
    // hash psw with bcrypt
    static async hash(password: string): Promise<string> {
        const saltRounds = 12; // Cost factor (12 is good balance)
        return bcrypt.hash(password, saltRounds);
    }

    // compare psw to hash
    static async compare(password: string, hash: string): Promise<boolean> {
        return bcrypt.compare(password, hash);
    }

    // Validate password strength: 8+ chars, uppercase, number, special char
    static validateStrength(password: string): { valid: boolean; errors: string[] } {
        const errors: string[] = []
        if (password.length < 8) {
            errors.push('Password must be at least 8 characters');
        }
        if (!/[A-Z]/.test(password)) {
            errors.push('Password must contain uppercase letter');
        }
        if (!/[0-9]/.test(password)) {
            errors.push('Password must contain number');
        }
        if (!/[@$!%*?&]/.test(password)) {
            errors.push('Password must contain special character (@$!%*?&)');
        }
        return {
            valid: errors.length === 0,
            errors,
        };
    }
}

export class JWTService {
    private static readonly ACCESS_TOKEN_EXPIRY = '15m';
    private static readonly REFRESH_TOKEN_EXPIRY = '7d';

    private static validateSecrets(): void {
        if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
            throw new Error('JWT secrets are not configured');
        }
    }

    static generateAccessToken(payload: Omit<JWTPayload, 'iat' | 'exp'>): string {
        this.validateSecrets();
        return jwt.sign(payload, process.env.JWT_SECRET!, {
            expiresIn: this.ACCESS_TOKEN_EXPIRY,
            algorithm: 'HS256'
        });
    }

    static generateRefreshToken(userId: string): string {
        this.validateSecrets();
        return jwt.sign({ sub: userId}, process.env.JWT_REFRESH_SECRET!, {
            expiresIn: this.REFRESH_TOKEN_EXPIRY,
            algorithm: 'HS256',
            jti: uuidv4()
        });
    }

    static verifyAccessToken(token: string): JWTPayload | null {
        this.validateSecrets();
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET!, { 
                algorithms: ['HS256']
            });
            return decoded as JWTPayload;
        } catch (error) {
            return null;
        }
    }

    static verifyRefreshToken(token: string): { sub: string, jti: string } | null {
        try {
            this.validateSecrets();
            const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET!, { 
                algorithms: ['HS256']
            });
            return decoded as { sub: string, jti: string };  
        } catch (error) {
            return null;
        }
    }

    // extract token from authorization header
    static extractToken(authHeader?: string): string | null {
        if (!authHeader) return null;
        const parts = authHeader.split(' ');
        if (parts.length !== 2 || parts[0]!.toLowerCase() !== 'bearer') {
            return null;
        }
        return parts[1] || null;
    }
}

export const authMiddleware = (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers.authorization;
        // Handle cases where auth header might be an array
        const headerValue = Array.isArray(authHeader) ? authHeader[0] : authHeader;
        const token = JWTService.extractToken(headerValue);
        if (!token) { // missing token to be handled by auth guards
            req.user = undefined;
            return next();
        }

        const payload = JWTService.verifyAccessToken(token);
        if (!payload) { // invalid/expired token
            req.user = undefined;
            return next();
        }

        req.user = payload;
        req.ip = req.ip || req.socket.remoteAddress || 'unknown';
        req.userAgent = req.get('user-agent') || 'unknown';
        next();
        
    } catch (error) {
        console.error('Auth middleware error: ', error);
        next();
    }
}

// Authorization Guards 

export const requireAuth = (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
        return res.status(401).json({
            error: 'UNAUTHORIZED',
            message: 'Authentication required'
        });
    }
    next();
};

export const requireRole = (...roles: UserRole[]) => {
    return (req: AuthRequest, res: Response, next: NextFunction) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'UNAUTHORIZED',
                message: 'Authentication required'
            });
        };

        if (!roles.includes(req.user.role)) {
            return res.status(301).json({
                error: 'INSUFFICIENT_PERMISSION',
                message: `Requires one of ${roles.join(',' )}`
            });
        };

        next();
    }
}

export const requirePermission = () => {}
