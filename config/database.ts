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

  const configuredUri = process.env.MONGODB_URI?.trim();
  const hasValidScheme = Boolean(
    configuredUri && (configuredUri.startsWith('mongodb://') || configuredUri.startsWith('mongodb+srv://'))
  );

  if (hasValidScheme && configuredUri && configuredUri !== 'inmemory') {
    try {
      console.log('[Database] Connecting to configured MongoDB instance...');
      await mongoose.connect(configuredUri, {
        serverSelectionTimeoutMS: 5000,
      });
      activeUri = configuredUri;
      // Mask password if present in URI for safe logging
      const sanitizedUri = configuredUri.replace(/\/\/[^@]+@/, '//***:***@');
      console.log(`[Database] Successfully connected to MongoDB at ${sanitizedUri}`);
      return activeUri;
    } catch (err: any) {
      console.warn(`[Database] Failed to connect to configured URI (${err.message}). Starting embedded MongoDB...`);
    }
  }

  const isTest = process.env.NODE_ENV === 'test' || process.argv.some((a) => a.includes('test'));

  if (!isTest) {
    // Spin up embedded real MongoDB with disk persistence for dev server
    console.log('[Database] Initializing embedded MongoDB server with local persistence...');
    const dataDir = path.resolve(process.cwd(), '.data/mongodb');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    try {
      memoryServer = await MongoMemoryServer.create({
        instance: {
          dbName: 'secure_auth_db',
          dbPath: dataDir,
          storageEngine: 'wiredTiger',
        },
      });
    } catch (err: any) {
      console.warn(`[Database] Failed to bind custom dbPath, falling back to standard memory server`);
      memoryServer = await MongoMemoryServer.create({
        instance: {
          dbName: 'secure_auth_db',
        },
      });
    }
  } else {
    // Isolated in-memory instance for test runner to prevent directory lock conflicts
    memoryServer = await MongoMemoryServer.create({
      instance: {
        dbName: 'secure_auth_test_db',
      },
    });
  }

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
