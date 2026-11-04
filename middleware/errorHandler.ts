import { Request, Response, NextFunction } from 'express';

interface CustomError extends Error {
  status?: number;
  statusCode?: number;
  code?: number;
  keyValue?: Record<string, any>;
  errors?: Record<string, any>;
}

/**
 * Centralized error handling middleware.
 * Prevents information leakage (stack traces, internal DB errors, connection strings).
 */
export function errorHandler(
  err: CustomError,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  const statusCode = err.status || err.statusCode || 500;

  // Safe operational logging (no sensitive credentials/passwords)
  console.error(`[Error Handler] ${err.name || 'Error'}: ${err.message}`);

  // Handle Mongoose duplicate key error (code 11000)
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue || {})[0] || 'field';
    res.status(409).json({
      success: false,
      error: `An account with this ${field} already exists.`,
    });
    return;
  }

  // Handle Mongoose validation error
  if (err.name === 'ValidationError' && err.errors) {
    const messages = Object.values(err.errors).map((e: any) => e.message);
    res.status(400).json({
      success: false,
      error: messages[0] || 'Validation failed.',
      details: messages,
    });
    return;
  }

  // Handle JSON parse error from express.json()
  if (err.name === 'SyntaxError' && 'body' in err) {
    res.status(400).json({
      success: false,
      error: 'Malformed JSON payload in request body.',
    });
    return;
  }

  // Generic internal server error - never leak stack traces to client
  res.status(statusCode).json({
    success: false,
    error: statusCode === 500 ? 'An unexpected internal error occurred. Please try again later.' : err.message,
  });
}
