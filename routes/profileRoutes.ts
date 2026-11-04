import { Router, Response } from 'express';
import { requireAuth, AuthenticatedRequest } from '../middleware/authentication.ts';

const router = Router();

/**
 * GET /api/profile
 * Returns the currently authenticated user's profile details.
 * Derives user identity exclusively from the verified server-side session.
 */
router.get('/', requireAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const user = req.user!;

  res.status(200).json({
    success: true,
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    },
  });
});

export default router;
