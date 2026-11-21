import { MongoClient, Db } from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const client = new MongoClient(uri);
let db: Db;
// Database name can be provided via MONGODB_DB_NAME env variable, defaulting to 'mentor-lagbe'
const dbName = process.env.MONGODB_DB_NAME || 'mentor-lagbe';

export async function connectToDatabase() {
  if (!db) {
    await client.connect();
    db = client.db(dbName);
    console.log(`Connected to MongoDB database: ${dbName}`);
  }
  return db;
}

export function getDb(): Db {
  if (!db) throw new Error('Database not connected');
  return db;
}

