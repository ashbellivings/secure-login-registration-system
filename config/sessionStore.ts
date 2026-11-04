import MongoStore from 'connect-mongo';

let storeInstance: any = null;

/**
 * Initializes and provides the singleton MongoStore instance for server-side sessions.
 */
export function getSessionStore(mongoUrl?: string): any {
  if (!storeInstance && mongoUrl) {
    storeInstance = MongoStore.create({
      mongoUrl,
      collectionName: 'sessions',
      ttl: 60 * 60, // 1 hour session lifetime
      autoRemove: 'native',
    });
  }
  return storeInstance;
}
