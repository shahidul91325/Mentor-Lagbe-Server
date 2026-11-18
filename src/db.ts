/**
 * MongoDB connection helper.
 *
 * One client instance is reused for the whole server lifetime.
 * `connectToDatabase()` runs once at startup (see index.ts),
 * `getDb()` gives route handlers access to the database.
 */
import { MongoClient, type Db } from "mongodb";
import { env } from "./env";

let client: MongoClient | null = null;
let database: Db | null = null;

export async function connectToDatabase(): Promise<void> {
  if (database) return;

  client = new MongoClient(env.mongodbUri);
  await client.connect();
  database = client.db(env.mongodbDbName);

  console.log(`[db] Connected to MongoDB database "${env.mongodbDbName}"`);
}

/** Returns the database handle. Throws if the server has not connected yet. */
export function getDb(): Db {
  if (!database) {
    throw new Error("Database not connected. Call connectToDatabase() before using getDb().");
  }
  return database;
}

export async function closeDatabase(): Promise<void> {
  await client?.close();
  client = null;
  database = null;
}
