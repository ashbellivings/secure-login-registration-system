import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import fs from 'fs';
import path from 'path';

let memoryServer: MongoMemoryServer | null = null;
let activeUri = '';

/**
 * Initializes the MongoDB database connection.
 * Connects to process.env.MONGODB_URI if specified.
 * Falls back to an embedded MongoMemoryServer for standalone zero-config execution.
 */
export async function connectDB(): Promise<string> {
  if (mongoose.connection.readyState === 1) {
    return activeUri;
  }

  const isProd = process.env.NODE_ENV === 'production';
  const configuredUri = process.env.MONGODB_URI?.trim();
  const hasValidScheme = Boolean(
    configuredUri && (configuredUri.startsWith('mongodb://') || configuredUri.startsWith('mongodb+srv://'))
  );

  // In production, strictly require a valid real MongoDB URI; never fall back to an in-memory database
  if (isProd) {
    if (!configuredUri || !hasValidScheme) {
      throw new Error(
        '[Database] FATAL: Production environment requires a valid MONGODB_URI starting with "mongodb://" or "mongodb+srv://". Embedded/in-memory database fallback is strictly prohibited in production.'
      );
    }

    console.log('[Database] Connecting to production MongoDB instance...');
    try {
      await mongoose.connect(configuredUri, {
        serverSelectionTimeoutMS: 10000,
      });
      activeUri = configuredUri;
      const sanitizedUri = configuredUri.replace(/\/\/[^@]+@/, '//***:***@');
      console.log(`[Database] Successfully connected to production MongoDB at ${sanitizedUri}`);
      return activeUri;
    } catch (err: any) {
      throw new Error(
        `[Database] FATAL: Failed to connect to production MongoDB (${err.message}). Server startup aborted to prevent unsafe state.`
      );
    }
  }

  // Development & Test Mode: Attempt connection to configured URI if valid
  if (hasValidScheme && configuredUri && configuredUri !== 'inmemory') {
    try {
      console.log('[Database] Connecting to configured MongoDB instance...');
      await mongoose.connect(configuredUri, {
        serverSelectionTimeoutMS: 5000,
      });
      activeUri = configuredUri;
      const sanitizedUri = configuredUri.replace(/\/\/[^@]+@/, '//***:***@');
      console.log(`[Database] Successfully connected to MongoDB at ${sanitizedUri}`);
      return activeUri;
    } catch (err: any) {
      console.warn(`[Database] Failed to connect to configured URI (${err.message}). Starting embedded MongoDB...`);
    }
  }

  // Development & Test Mode fallback: Initialize embedded MongoMemoryServer
  const isTest = process.env.NODE_ENV === 'test' || process.argv.some((a) => a.includes('test'));
  console.log('[Database] Initializing embedded MongoDB memory server...');
  memoryServer = await MongoMemoryServer.create({
    instance: {
      dbName: isTest ? 'secure_auth_test_db' : 'secure_auth_db',
    },
  });

  activeUri = memoryServer.getUri();
  await mongoose.connect(activeUri);
  console.log('[Database] Connected to embedded MongoDB instance.');
  console.log('[Database] Real Mongoose schemas, queries, and unique indexes are active.');

  return activeUri;
}

export function getActiveDbUri(): string {
  return activeUri;
}

export async function disconnectDB(): Promise<void> {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
  }
  if (memoryServer) {
    await memoryServer.stop();
    memoryServer = null;
  }
  console.log('[Database] Disconnected from MongoDB.');
}
