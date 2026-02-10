import express from 'express';
import type { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid';

import {
  authMiddleware,
  checkTokenBlacklist,
  apiLimiter,
} from './auth.middleware';

import {
  authRouter,
  usersRouter,
  tasksRouter,
  auditRouter,
  dashboardRouter,
  errorHandler,
} from './api.endpoints';

dotenv.config();

export const createApp = (): Express => {

  const app = express();

    // Helmet: Set various HTTP headers for security
  app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                scriptSrc: ["'self'"],
            },
        },
        hsts: {
            maxAge: 31536000, // 1 year in seconds
            includeSubDomains: true,
            preload: true,
        },
    })
  );

  const allowedOrigins = (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',');

  app.use(
    cors({
        origin: (origin, callback) => {
            if (!origin || allowedOrigins.includes(origin)) {
                callback(null, true);
            } else {
                callback(new Error('Not allowed by CORS'));
            }
        },
        credentials: true,
        methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization'],
        maxAge: 86400, // 24 hours
        })
    );

  app.use(
    morgan(':remote-addr :method :url :status :response-time ms - :res[content-length]')
  );

  // Parse body 
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ limit: '10mb', extended: true }));

  app.use((req: Request, res: Response, next: NextFunction) => {
    const requestId = req.get('x-request-id') || uuidv4();
    req.id = requestId;
    res.setHeader('x-request-id', requestId);
    next();
  });

  // Extend Request to include id
  declare global {
    namespace Express {
      interface Request {
        id?: string;
      }
    }
  }

  // Auth middleware 
  app.use(authMiddleware);
  app.use(checkTokenBlacklist);

  app.use('/api/', apiLimiter);


  app.get('/health', (req: Request, res: Response) => {
    res.status(200).json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    });
  });


  // Auth routes (no auth required for login)
  app.use('/api/auth', authRouter);

  // Protected routes
  app.use('/api/users', usersRouter);
  app.use('/api/tasks', tasksRouter);
  app.use('/api/audit', auditRouter);
  app.use('/api/dashboard', dashboardRouter);


  const swaggerUi = require('swagger-ui-express');
  const swaggerDoc = require('./swagger.json'); 

  app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerDoc));

  app.use((req: Request, res: Response) => {
    res.status(404).json({
      error: 'NOT_FOUND',
      message: `Route ${req.method} ${req.path} not found`,
      request_id: req.id,
    });
  });

  app.use(errorHandler);

  return app;
};

const PORT = parseInt(process.env.PORT || '3000');
const NODE_ENV = process.env.NODE_ENV || 'development';


export const startServer = async () => {
  const app = createApp();

  // Add DB connection here

  // import { initializeDatabase } from './database';
  // try {
  //   await initializeDatabase();
  //   console.log('Database connected');
  // } catch (error) {
  //   console.error('Database connection failed:', error);
  //   process.exit(1);
  // }

  const server = app.listen(PORT, () => {
    console.log("Server started....");
  });

  // Shutdown 
  process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down...');
    server.close(async () => {
      // await db.close();
      console.log('Server closed');
      process.exit(0);
    });
  });

  process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down...');
    server.close(async () => {
      // await db.close();
      console.log('Server closed');
      process.exit(0);
    });
  });

  return server;
};


if (require.main === module) {
  startServer().catch((error) => {
    console.error('Failed to start server:', error);
    process.exit(1);
  });
}

export default createApp;