import { Router, Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import { User } from '../models/User.ts';
import { requireAuth, requireRole, AuthenticatedRequest } from '../middleware/authentication.ts';
import { authLimiter, getOrCreateCsrfToken } from '../middleware/security.ts';
import { getSessionStore } from '../config/sessionStore.ts';

const router = Router();

// Bcrypt salt work factor (default 12 for high security / balanced latency)
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);

// Pre-computed dummy hash to prevent side-channel timing attacks when user does not exist
// This ensures constant-time verification regardless of whether the email exists in DB
const DUMMY_HASH = '$2a$12$L7FekjPskL9q9RkVlI8tY.c37cI/Y5tNqG55w0N1d2rU2JkJ9d3uW';

// Email validation regular expression (RFC 5322 compatible)
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

/**
 * GET /api/csrf-token
 * Issues a session-bound CSRF token for state-changing requests.
 */
router.get('/csrf-token', (req: Request, res: Response) => {
  const token = getOrCreateCsrfToken(req);
  res.json({ success: true, csrfToken: token });
});

/**
 * POST /api/register
 * Registers a new user account with secure password hashing.
 */
router.post('/register', authLimiter, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { name, email, password } = req.body;

    // 1. Backend Input Validation: Presence check
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      res.status(400).json({
        success: false,
        error: 'Full name is required.',
      });
      return;
    }

    if (!email || typeof email !== 'string' || email.trim().length === 0) {
      res.status(400).json({
        success: false,
        error: 'Email address is required.',
      });
      return;
    }

    if (!password || typeof password !== 'string') {
      res.status(400).json({
        success: false,
        error: 'Password is required.',
      });
      return;
    }

    const trimmedName = name.trim();
    const normalizedEmail = email.trim().toLowerCase();

    // 2. Name validation
    if (trimmedName.length < 2 || trimmedName.length > 50) {
      res.status(400).json({
        success: false,
        error: 'Name must be between 2 and 50 characters in length.',
      });
      return;
    }

    // 3. Email syntax validation
    if (!EMAIL_REGEX.test(normalizedEmail) || normalizedEmail.length > 100) {
      res.status(400).json({
        success: false,
        error: 'Please provide a valid email address.',
      });
      return;
    }

    // 4. Password policy validation
    // Minimum 8 characters; maximum 72 characters to prevent bcrypt silent truncation
    if (password.length < 8) {
      res.status(400).json({
        success: false,
        error: 'Password must be at least 8 characters long.',
      });
      return;
    }

    if (password.length > 72) {
      res.status(400).json({
        success: false,
        error: 'Password exceeds maximum permitted length (72 characters).',
      });
      return;
    }

    // 5. Check if user already exists
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      res.status(409).json({
        success: false,
        error: 'An account with this email address already exists.',
      });
      return;
    }

    // 6. Secure Password Hashing with Bcrypt
    // Salt is automatically generated with configured cost factor
    const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

    // 7. Store user record in MongoDB (only the hash is stored, never plaintext)
    const newUser = new User({
      name: trimmedName,
      email: normalizedEmail,
      passwordHash,
    });

    await newUser.save();

    // 8. Return safe response without password or hash
    res.status(201).json({
      success: true,
      message: 'Account successfully registered. You may now log in.',
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        createdAt: newUser.createdAt,
      },
    });
  } catch (err: any) {
    next(err);
  }
});

/**
 * POST /api/login
 * Authenticates user credentials and establishes a protected server-side session.
 */
router.post('/login', authLimiter, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { email, password } = req.body;

    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
      res.status(400).json({
        success: false,
        error: 'Email and password are required.',
      });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Query user by normalized email
    const user = await User.findOne({ email: normalizedEmail });

    // Defense against timing attack: if user not found, perform dummy bcrypt compare
    if (!user) {
      await bcrypt.compare(password, DUMMY_HASH);
      res.status(401).json({
        success: false,
        error: 'Invalid email or password.',
      });
      return;
    }

    // Verify password hash with bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

    if (!isPasswordValid) {
      res.status(401).json({
        success: false,
        error: 'Invalid email or password.',
      });
      return;
    }

    // Mitigate Session Fixation: Regenerate session ID upon successful login
    const oldCsrf = req.session.csrfToken;
    req.session.regenerate((err) => {
      if (err) {
        return next(err);
      }

      // Configure cookie attributes based on request protocol & environment
      const isProd = process.env.NODE_ENV === 'production';
      const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https' || isProd;
      if (req.session.cookie) {
        req.session.cookie.secure = Boolean(isHttps);
        req.session.cookie.sameSite = isProd ? 'lax' : (isHttps ? 'none' : 'lax');
      }

      // Establish authenticated session state on server
      req.session.userId = user._id.toString();
      req.session.userEmail = user.email;
      req.session.csrfToken = oldCsrf || getOrCreateCsrfToken(req);

      // Save session explicitly before responding
      req.session.save((saveErr) => {
        if (saveErr) {
          return next(saveErr);
        }

        res.status(200).json({
          success: true,
          message: 'Authentication successful. Session established.',
          sessionId: req.sessionID,
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role || 'user',
          },
        });
      });
    });
  } catch (err: any) {
    next(err);
  }
});

/**
 * GET /api/profile
 * Returns authenticated user's private profile.
 * Protected by requireAuth middleware.
 */
router.get('/profile', requireAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const user = req.user!;
  res.status(200).json({
    success: true,
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role || 'user',
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    },
  });
});

/**
 * GET /api/admin/users
 * Protected by requireAuth AND requireRole('admin').
 * Demonstrates Role-Based Access Control (RBAC).
 */
router.get('/admin/users', requireAuth, requireRole('admin'), async (_req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const allUsers = await User.find({}).select('name email role createdAt');
    res.status(200).json({
      success: true,
      message: 'Administrative privileges verified.',
      totalUsers: allUsers.length,
      users: allUsers.map((u) => ({
        id: u._id,
        name: u.name,
        email: u.email,
        role: u.role || 'user',
        createdAt: u.createdAt,
      })),
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/logout
 * Destroys server-side session and clears authentication cookie.
 */
router.post('/logout', (req: Request, res: Response, next: NextFunction): void => {
  const headerSessionId = (req.headers['x-session-id'] as string)?.trim();
  if (headerSessionId) {
    const store = getSessionStore();
    if (store) {
      store.destroy(headerSessionId, () => {});
    }
  }

  const isProd = process.env.NODE_ENV === 'production';
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https' || isProd;

  // Invalidate cookie in client browser
  res.clearCookie('connect.sid', {
    path: '/',
    httpOnly: true,
    sameSite: isProd ? 'lax' : (isHttps ? 'none' : 'lax'),
    secure: Boolean(isHttps),
  });

  if (!req.session || !req.session.userId) {
    res.status(200).json({
      success: true,
      message: 'Logged out successfully.',
    });
    return;
  }

  req.session.destroy((err) => {
    if (err) {
      return next(err);
    }

    res.status(200).json({
      success: true,
      message: 'Session destroyed. Logged out successfully.',
    });
  });
});

/**
 * GET /api/auth/status
 * Safe endpoint to query current authentication state.
 */
router.get('/auth/status', async (req: Request, res: Response): Promise<void> => {
  let effectiveUserId = req.session?.userId;

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
        }
      }
    }
  }

  if (!effectiveUserId) {
    res.status(200).json({
      authenticated: false,
      user: null,
    });
    return;
  }

  try {
    const user = await User.findById(effectiveUserId).select('name email');
    if (!user) {
      if (req.session) {
        req.session.destroy(() => {});
      }
      res.status(200).json({
        authenticated: false,
        user: null,
      });
      return;
    }

    res.status(200).json({
      authenticated: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch {
    res.status(200).json({
      authenticated: false,
      user: null,
    });
  }
});

/**
 * GET /api/security/audit-info
 * Cybersecurity inspection endpoint.
 * Protected with requireAuth so audit data is not exposed publicly.
 */
router.get('/security/audit-info', requireAuth, async (_req: Request, res: Response): Promise<void> => {
  try {
    const userCount = await User.countDocuments();
    // Retrieve sample user record showing masked password hash format for demonstration
    const sampleUser = await User.findOne().sort({ createdAt: -1 });

    let maskedHashSample = 'No users registered yet';
    if (sampleUser && sampleUser.passwordHash) {
      // Show algorithm identifier ($2a$12$) and truncated salt/hash structure
      const parts = sampleUser.passwordHash.split('$');
      maskedHashSample = `$${parts[1]}$${parts[2]}$${parts[3].substring(0, 10)}...[MASKED_50_CHARS]`;
    }

    res.status(200).json({
      success: true,
      controls: {
        passwordHashing: {
          algorithm: 'Bcrypt ($2a$)',
          workFactor: BCRYPT_SALT_ROUNDS,
          plaintextStored: false,
          sampleStoredHash: maskedHashSample,
        },
        sessionManagement: {
          store: 'MongoDB Server-Side Session Store (connect-mongo)',
          sessionRegenerationOnLogin: true,
          cookieHttpOnly: true,
          cookieSameSite: 'Lax',
          cookieTtlMinutes: 60,
        },
        rateLimiting: {
          windowMinutes: 15,
          maxAttemptsPerWindow: 20,
          protectedEndpoints: ['/api/register', '/api/login'],
        },
        databaseSecurity: {
          databaseEngine: 'MongoDB',
          ormOdm: 'Mongoose',
          uniqueEmailIndex: true,
          totalRegisteredUsers: userCount,
        },
        httpHeaders: {
          helmetActive: true,
          xContentTypeOptions: 'nosniff',
          frameguard: 'SAMEORIGIN',
          hidePoweredBy: true,
        },
      },
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: 'Failed to retrieve audit info.' });
  }
});

/**
 * GET /api/security/inspect-database
 * Available exclusively in non-production/testing mode for development evaluation.
 * In production, this endpoint is completely disabled to avoid public database exposure.
 */
router.get('/security/inspect-database', async (_req: Request, res: Response): Promise<void> => {
  if (process.env.NODE_ENV === 'production') {
    res.status(404).json({ success: false, error: 'Not found.' });
    return;
  }

  try {
    const rawUsers = await User.find({}).select('name email passwordHash createdAt updatedAt');
    res.status(200).json({
      success: true,
      database: 'MongoDB',
      collection: 'users',
      totalRecords: rawUsers.length,
      records: rawUsers.map((u) => ({
        id: u._id,
        name: u.name,
        email: u.email,
        passwordHash: u.passwordHash,
        createdAt: u.createdAt,
      })),
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
