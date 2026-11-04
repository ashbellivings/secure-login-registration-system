import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';

// Strict rate limiter for authentication attempts (Registration & Login)
// Defends against automated credential stuffing and password-guessing
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes window
  max: 20, // Limit each IP to 20 requests per windowMs
  standardHeaders: true, // Return standard RateLimit headers (draft-7)
  legacyHeaders: false, // Disable X-RateLimit-* headers
  message: {
    success: false,
    error: 'Too many authentication attempts from this IP address. Please try again after 15 minutes.',
  },
  statusCode: 429,
});

// General API rate limiter
export const generalApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests. Please slow down and try again later.',
  },
  statusCode: 429,
});

/**
 * Generates or retrieves the session-bound CSRF token.
 */
export function getOrCreateCsrfToken(req: Request): string {
  if (!req.session) {
    return crypto.randomBytes(32).toString('hex');
  }
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

/**
 * Validates the CSRF token on state-changing requests (POST, PUT, DELETE, PATCH).
 * The client sends the token in the 'X-CSRF-Token' header or '_csrf' body field.
 */
export function verifyCsrfToken(req: Request, res: Response, next: NextFunction): void {
  // Safe HTTP methods do not alter state
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  // Exempt automated internal test endpoint if run in development test mode
  if (req.path === '/api/security/run-automated-tests') {
    return next();
  }

  const sessionToken = req.session?.csrfToken;
  const clientToken = (req.headers['x-csrf-token'] as string) || req.body?._csrf;

  if (!sessionToken || !clientToken || !crypto.timingSafeEqual(Buffer.from(sessionToken), Buffer.from(clientToken))) {
    res.status(403).json({
      success: false,
      error: 'Invalid or missing CSRF token. Request rejected for security.',
    });
    return;
  }

  next();
}
