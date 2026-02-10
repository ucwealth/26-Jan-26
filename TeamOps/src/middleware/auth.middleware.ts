import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { z } from 'zod';
import rateLimit from 'express-rate-limit';


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
    };
};

// Requires permission: check roles_permission table
export const requirePermission = (permission: string) => {
    return async (req: AuthRequest, res: Response, next: NextFunction) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'UNAUTHORIZED',
                message: 'Authentication required'
            });
        };

        const hasPermission = await checkUserPermission(req.user.id, permission);
        if (!hasPermission) {
            return res.status(301).json({
                error: 'INSUFFICIENT_PERMISSION',
                message: `Permission required: ${permission}`
            });
        };

        next();
    };
};

export const requireOwnerOrAdmin = (paramName: string = 'id') => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Authentication required',
      });
    }

    const targetId = req.params[paramName];
    const isOwner = req.user.id === targetId;
    const isAdmin = req.user.role === UserRole.ADMIN;

    if (!isOwner && !isAdmin) {
      return res.status(403).json({
        error: 'INSUFFICIENT_PERMISSION',
        message: 'Can only modify your own resource',
      });
    }

    next();
  };
};

// Check permissions in DB
async function checkUserPermission(userId: string, permission: string): Promise<boolean> {
    // implement with DB query
    // const user = await User.findById(userId);
  // const permissions = await RolePermissions.findAll({ role: user.role });
  // return permissions.some(p => p.permission === permission);

  return true;
}

// Input Validation
export const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password required'),
});

export const registerSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(12, 'Password must be at least 12 characters'),
  first_name: z.string().min(1),
  last_name: z.string().min(1),
});

export const refreshTokenSchema = z.object({
  refresh_token: z.string().min(1, 'Refresh token required'),
});

export type LoginInput = z.infer<typeof loginSchema>;
export type RegisterInput = z.infer<typeof registerSchema>;


// Token Blacklist(For Logout)
const tokenBlacklist = new Set<string>();

export class TokenBlacklistService {
  static blacklist(token: string): void {
    tokenBlacklist.add(token);
  }

  static isBlacklisted(token: string): boolean {
    return tokenBlacklist.has(token);
  }

  /**
   * In production with Redis:
   * await redis.setex(`blacklist:${token}`, expirySeconds, '1');
   * return await redis.exists(`blacklist:${token}`);
   */
}

export const checkTokenBlacklist = (req: AuthRequest, res: Response, next: NextFunction) => {
  const token = JWTService.extractToken(req.headers.authorization);

  if (token && TokenBlacklistService.isBlacklisted(token)) {
    return res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Token has been revoked',
    });
  }

  next();
};


// Rate Limiting

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  keyGenerator: (req) => req.ip || 'unknown',
  message: 'Too many login attempts, please try again later',
  standardHeaders: true, // Return rate limit info in headers
  skip: (req) => process.env.NODE_ENV === 'test', // Skip in tests
});


export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // For API endpoints, 100 requests per 15 minutes per user
  max: 100,
  keyGenerator: (req: any) => (req as AuthRequest).user?.id || req.ip || 'unknown',
  standardHeaders: true,
  skip: (req) => process.env.NODE_ENV === 'test',
});

export default {
  PasswordService,
  JWTService,
  authMiddleware,
  requireAuth,
  requireRole,
  requirePermission,
  requireOwnerOrAdmin,
  loginLimiter,
  apiLimiter,
  TokenBlacklistService,
  checkTokenBlacklist,
  loginSchema,
  registerSchema,
  refreshTokenSchema,
};
