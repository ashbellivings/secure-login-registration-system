import { Request, Response, NextFunction } from 'express';
import { User, type IUser } from '../models/User.ts';
import { getSessionStore } from '../config/sessionStore.ts';

// Extend Express Request interface to include session user properties
declare module 'express-session' {
  interface SessionData {
    userId?: string;
    userEmail?: string;
    csrfToken?: string;
  }
}

export interface AuthenticatedRequest extends Request {
  user?: IUser;
}

/**
 * Middleware enforcing server-side session authentication.
 * Derives user identity exclusively from verified server session state.
 * Supports standard HttpOnly cookies and X-Session-ID header fallback for cross-origin iframes.
 */
export async function requireAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    let effectiveUserId = req.session?.userId;

    // Fallback: If browser blocked third-party cookies in an iframe, check header session ID against server store
    if (!effectiveUserId) {
      const headerSessionId = (req.headers['x-session-id'] as string)?.trim();
      if (headerSessionId) {
        const store = getSessionStore();
        if (store) {
          const sessionData: any = await new Promise((resolve) => {
            store.get(headerSessionId, (err: any, data: any) => {
              if (err || !data) return resolve(null);
              resolve(data);
            });
          });

          if (sessionData?.userId) {
            effectiveUserId = sessionData.userId;
            // Sync req.session for subsequent handlers
            if (req.session) {
              req.session.userId = sessionData.userId;
              req.session.userEmail = sessionData.userEmail;
            }
          }
        }
      }
    }

    if (!effectiveUserId) {
      res.status(401).json({
        success: false,
        error: 'Unauthorized. You must be logged in to access this resource.',
      });
      return;
    }

    const user = await User.findById(effectiveUserId).select('-passwordHash');

    if (!user) {
      // Session references a user that no longer exists in DB
      if (req.session) {
        req.session.destroy(() => {});
      }
      res.status(401).json({
        success: false,
        error: 'Unauthorized. Associated account was not found. Please log in again.',
      });
      return;
    }

    req.user = user;
    next();
  } catch (err: any) {
    next(err);
  }
}

/**
 * Middleware enforcing Role-Based Access Control (RBAC).
 * Ensures only users with the required role (e.g., 'admin') can access protected administrative routes.
 */
export function requireRole(requiredRole: 'admin' | 'user') {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Unauthorized. Authentication required.',
      });
      return;
    }

    if (req.user.role !== requiredRole && req.user.role !== 'admin') {
      res.status(403).json({
        success: false,
        error: `Forbidden. Insufficient permissions. Required role: '${requiredRole}'. Your role: '${req.user.role}'.`,
      });
      return;
    }

    next();
  };
}
