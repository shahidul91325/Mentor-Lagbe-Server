import { MongoClient, Db } from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const dbName = process.env.MONGODB_DB_NAME || 'mentor-lagbe';

const client = new MongoClient(uri, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 10000,
});

let db: Db | null = null;
let connectionPromise: Promise<Db> | null = null;

export async function connectToDatabase(): Promise<Db> {
  if (db) return db;
  if (!connectionPromise) {
    connectionPromise = (async () => {
      await client.connect();
      const database = client.db(dbName);
      await database.command({ ping: 1 });
      db = database;
      console.log(`Connected to MongoDB database: ${dbName}`);
      return database;
    })().catch((err) => {
      connectionPromise = null;
      db = null;
      throw err;
    });
  }
  return connectionPromise;
}

export function getDb(): Db {
  if (!db) throw new Error('Database not connected');
  return db;
}

export async function ensureDatabase(): Promise<Db> {
  return connectToDatabase();
}
