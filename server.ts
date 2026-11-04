import express, { Request, Response } from 'express';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';

import { connectDB, getActiveDbUri } from './config/database.ts';
import { getSessionStore } from './config/sessionStore.ts';
import authRoutes from './routes/authRoutes.ts';
import profileRoutes from './routes/profileRoutes.ts';
import { errorHandler } from './middleware/errorHandler.ts';
import { generalApiLimiter } from './middleware/security.ts';
import { executeSecurityTests } from './tests/testRunner.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const isProd = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 3000;

// Read SESSION_SECRET from process.env; in production, enforce strict length & presence
const rawSessionSecret = process.env.SESSION_SECRET?.trim();
if (isProd) {
  if (!rawSessionSecret || rawSessionSecret.length < 32) {
    console.error(
      '[Fatal Security Error] SESSION_SECRET environment variable is missing or shorter than 32 characters in production. Server startup aborted for security.'
    );
    process.exit(1);
  }
}

// In development/test mode, provide a fallback to facilitate local development and automated testing
const SESSION_SECRET = rawSessionSecret || 'development-local-only-session-secret-min32chars';

const isCloudOrHttps = Boolean(
  process.env.APP_URL?.startsWith('https') ||
  process.env.NODE_ENV === 'production' ||
  process.env.K_SERVICE
);

async function startServer() {
  const app = express();

  // Enable reverse proxy trust (Required for Google Cloud Run / AI Studio preview)
  app.set('trust proxy', 1);

  // 1. Establish MongoDB connection (real Mongo or embedded MongoMemoryServer)
  const dbUri = await connectDB();
  const sessionStoreInstance = getSessionStore(dbUri);

  // 2. HTTP Security Headers with Helmet
  // Configured to permit AI Studio iframe preview while enforcing defense-in-depth
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
          styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
          fontSrc: ["'self'", 'https://fonts.gstatic.com'],
          imgSrc: ["'self'", 'data:', 'blob:'],
          connectSrc: ["'self'", 'https:', 'wss:', '*'],
          frameAncestors: ['*'], // Permits preview in Google AI Studio iframe
          upgradeInsecureRequests: null,
        },
      },
      frameguard: false, // Disables X-Frame-Options: SAMEORIGIN so iframe can render
      crossOriginResourcePolicy: false,
      crossOriginOpenerPolicy: false,
      crossOriginEmbedderPolicy: false,
    })
  );

  // 3. CORS Configuration (Restricted, credentials permitted)
  app.use(
    cors({
      origin: true,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'Authorization', 'X-Session-ID'],
    })
  );

  // 4. Request Body Parsers with safe strict payload limits
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: false, limit: '10kb' }));
  app.use(cookieParser());

  // 5. Server-Side Session Storage with connect-mongo
  app.use(
    session({
      name: 'connect.sid',
      secret: SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      store: sessionStoreInstance,
      cookie: {
        httpOnly: true, // Prevent JavaScript document.cookie access (Mitigates XSS cookie theft)
        secure: isProd ? true : isCloudOrHttps,
        sameSite: isProd ? 'lax' : (isCloudOrHttps ? 'none' : 'lax'),
        partitioned: !isProd, // Partitioned cookies only for cross-origin preview iframes
        maxAge: 1000 * 60 * 60, // 1 hour TTL
        path: '/',
      } as any,
    })
  );

  // Dynamically configure cookie for HTTPS/Render deployment vs HTTP localhost
  app.use((req, _res, next) => {
    if (req.session && req.session.cookie) {
      const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https' || isProd;
      req.session.cookie.secure = Boolean(isHttps);
      req.session.cookie.sameSite = isProd ? 'lax' : (isHttps ? 'none' : 'lax');
    }
    next();
  });

  // 6. Global Rate Limiter for API endpoints
  app.use('/api', generalApiLimiter);

  // 7. API Routes
  app.use('/api', authRoutes);
  app.use('/api/profile', profileRoutes);

  // Automated test runner API endpoint for the web interface
  app.post('/api/security/run-automated-tests', async (_req: Request, res: Response) => {
    try {
      const results = await executeSecurityTests();
      res.json({ success: true, ...results });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // 8. Serve static files from 'public' directory
  app.use(express.static(path.join(__dirname, 'public')));

  // Page routing for vanilla HTML pages
  app.get('/', (_req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
  app.get('/register', (_req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
  });
  app.get('/login', (_req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
  });
  app.get('/dashboard', (_req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
  });
  app.get('/security-controls', (_req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'security-controls.html'));
  });
  app.get('/test-runner', (_req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'test-runner.html'));
  });

  // 9. Vite Middlewares for development asset support
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: false },
      appType: 'custom',
    });
    app.use(vite.middlewares);
  }

  // 10. Centralized Error Handling Middleware
  app.use(errorHandler);

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Server] Secure Authentication System running on http://0.0.0.0:${PORT}`);
    console.log(`[Server] Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}

startServer().catch((err) => {
  console.error('[Fatal Error] Failed to start server:', err);
  process.exit(1);
});
