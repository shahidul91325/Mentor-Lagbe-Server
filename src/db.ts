import { MongoClient, Db } from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/mentor_lagbe';
const client = new MongoClient(uri);
let db: Db;

export async function connectToDatabase() {
  if (!db) {
    await client.connect();
    db = client.db();
    console.log('Connected to MongoDB');
  }
  return db;
}

export function getDb(): Db {
  if (!db) throw new Error('Database not connected');
  return db;
}

