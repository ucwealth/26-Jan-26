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
    user?: JWTPayload;
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

    static generateAccessToken(payload: Omit<JWTPayload, 'iat' | 'exp'>): string {
        return jwt.sign(payload, process.env.JWT_SECRET!, {
            expiresIn: this.ACCESS_TOKEN_EXPIRY,
            algorithm: 'HS256'
        });
    }

    static generateRefreshToken(userId: string): string {
        return jwt.sign({ sub: userId}, process.env.JWT_REFRESH_SECRET!, {
            expiresIn: this.REFRESH_TOKEN_EXPIRY,
            algorithm: 'HS256',
            jti: uuidv4()
        });
    }

    static verifyAccessToken(token: string): JWTPayload | null {
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
            const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET!, { 
                algorithms: ['HS256']
            });
            return decoded as { sub: string, jti: string };  
        } catch (error) {
            return null;
        }
    }

    static extractToken() {

    }
}
