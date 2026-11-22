import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';
dotenv.config();
const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const dbName = process.env.MONGODB_DB_NAME || 'mentor-lagbe';
const client = new MongoClient(uri, {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 10000,
});
let db = null;
let connectionPromise = null;
export async function connectToDatabase() {
    if (db)
        return db;
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
export function getDb() {
    if (!db)
        throw new Error('Database not connected');
    return db;
}
export async function ensureDatabase() {
    return connectToDatabase();
}
