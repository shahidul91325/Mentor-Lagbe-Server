/* ============================================================================
 * MentorLagbe Server — Express application entry point
 * ---------------------------------------------------------------------------
 * Assignment rule: ALL CRUD route handlers and their MongoDB operations live
 * in this single file. Separate files are only allowed for database
 * connection, environment validation, BetterAuth, JWT middleware, shared
 * types, and other non-CRUD helpers.
 *
 * File sections:
 *   1. Imports and configuration
 *   2. App and middleware setup
 *   3. Health check
 *   4. BetterAuth integration (token minting & route forwarding)
 *   5. Profile APIs (GET /api/users/me, PATCH /api/users/me)
 *   6. Error handling
 *   7. Server startup
 * ==========================================================================*/

// ---------------------------------------------------------------------------
// 1. Imports and configuration
// ---------------------------------------------------------------------------
import express, { type ErrorRequestHandler } from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import { fromNodeHeaders, toNodeHandler } from "better-auth/node";
import { env } from "./src/env.js";
import { connectToDatabase, getDb } from "./src/db.js";
import { getAuth } from "./src/better-auth.js";
import { verifyToken, type AuthedRequest } from "./src/middleware/auth.js";
import { z } from "zod";
import { UserDoc, TuitionDoc, ApplicationDoc, ApplicationStatus, TuitionStatus } from "./src/types.js";
import { ObjectId } from "mongodb";

const IS_PRODUCTION = env.nodeEnv === "production";

// ---------------------------------------------------------------------------
// 2. App and middleware setup
// ---------------------------------------------------------------------------
const app = express();

// CORS: only the frontend origin may call this API (cookies included).
app.use(
  cors({
    origin: env.clientUrl,
    credentials: true,
  })
);

// Parse JSON request bodies.
app.use(express.json());

// ---------------------------------------------------------------------------
// 3. Health check
// ---------------------------------------------------------------------------
app.get("/api/health", async (_req, res) => {
  await getDb().command({ ping: 1 });

  res.json({
    status: "ok",
    message: "MentorLagbe API is running",
    database: "connected",
    environment: env.nodeEnv,
    timestamp: new Date().toISOString(),
  });
});

// ---------------------------------------------------------------------------
// 4. BetterAuth integration
// ---------------------------------------------------------------------------
/** Mints a MentorLagbe JWT for the current BetterAuth session. */
app.post("/api/auth/token", async (req, res) => {
  const session = await getAuth().api.getSession({ headers: fromNodeHeaders(req.headers) });

  if (!session) {
    res.status(401).json({ message: "No active session. Please sign in first." });
    return;
  }

  const token = jwt.sign({ sub: session.user.id }, env.jwtSecret, { expiresIn: "7d" });
  res.json({ token });
});

/** Forward all BetterAuth routes (sign‑up, sign‑in, session, etc.). */
let authNodeHandler: ReturnType<typeof toNodeHandler> | null = null;
app.use('/api/auth', (req, res, next) => {
  if (!authNodeHandler) {
    res.status(503).json({ message: 'Authentication service is not ready yet' });
    return;
  }
  return authNodeHandler(req, res);
});

// ---------------------------------------------------------------------------
// 5. Profile APIs
// ---------------------------------------------------------------------------
/** Returns the signed‑in user's profile (trusted server‑side data). */
app.get("/api/users/me", verifyToken, (req: AuthedRequest, res) => {
  res.json({ user: req.user });
});

/** Update the signed‑in user's profile.
 *  Allows only name, phone, bio, and image fields.
 *  Role and plan cannot be changed via this endpoint.
 */
app.patch("/api/users/me", verifyToken, async (req: AuthedRequest, res) => {
  const schema = z.object({
    name: z.string().optional(),
    phone: z.string().optional(),
    bio: z.string().optional(),
    image: z.string().optional(),
  }).strict();

  const parseResult = schema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ message: "Invalid profile data", issues: parseResult.error.issues });
  }
  const update = parseResult.data;

  // Prevent role or plan changes even if submitted.
  if ((req.body as any).role !== undefined || (req.body as any).plan !== undefined) {
    return res.status(400).json({ message: "Cannot change role or plan via profile update" });
  }

  try {
    const result = await getDb()
      .collection<UserDoc>("users")
      .updateOne({ _id: req.user!._id }, { $set: update, $currentDate: { updatedAt: true } });

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const refreshed = await getDb().collection<UserDoc>("users").findOne({ _id: req.user!._id });
    return res.json({ user: refreshed });
  } catch (e) {
    console.error("[profile update]", e);
    return res.status(500).json({ message: "Failed to update profile" });
  }
});

// ---------------------------------------------------------------------------
// 6. Tuition APIs
// ---------------------------------------------------------------------------
/** Schema for creating/updating a tuition. */
const tuitionSchema = z.object({
  title: z.string(),
  description: z.string(),
  price: z.number().nonnegative(),
  active: z.boolean().optional(),
}).strict();

/** Get public list of approved and active tuitions. */
app.get("/api/tuitions", async (req, res) => {
  const tuitions = await getDb()
    .collection<TuitionDoc>("tuitions")
    .find({ status: TuitionStatus.APPROVED, active: true })
    .toArray();
  res.json({ tuitions });
});

/** Get a single tuition if approved and active. */
app.get("/api/tuitions/:id", async (req, res) => {
  const id = req.params.id;
  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ message: "Invalid tuition id" });
  }
  const tuition = await getDb()
    .collection<TuitionDoc>("tuitions")
    .findOne({ _id: new ObjectId(id), status: TuitionStatus.APPROVED, active: true });
  if (!tuition) {
    return res.status(404).json({ message: "Tuition not found" });
  }
  res.json({ tuition });
});

/** Tutor creates a new tuition (defaults to pending, active). */
app.post("/api/tuitions", verifyToken, async (req: AuthedRequest, res) => {
  if (req.user?.role !== "tutor") {
    return res.status(403).json({ message: "Only tutors can create tuitions" });
  }

  const parseResult = tuitionSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ message: "Invalid tuition data", issues: parseResult.error.issues });
  }
  const data = parseResult.data;

  // Enforce plan limits
  const existingCount = await getDb()
    .collection<TuitionDoc>("tuitions")
    .countDocuments({ tutorId: req.user!._id });
  if (req.user!.plan === "free" && existingCount >= 2) {
    return res.status(403).json({ message: "Free tutors may create at most 2 tuitions" });
  }

  const tuition: Partial<TuitionDoc> = {
    tutorId: req.user!._id,
    title: data.title,
    description: data.description,
    price: data.price,
    active: data.active ?? true,
    status: TuitionStatus.PENDING,
    createdAt: new Date(),
  };

  const result = await getDb().collection<TuitionDoc>("tuitions").insertOne(tuition as TuitionDoc);
  const inserted = await getDb().collection<TuitionDoc>("tuitions").findOne({ _id: result.insertedId });
  res.status(201).json({ tuition: inserted });
});

/** Tutor updates own tuition. */
app.patch("/api/tuitions/:id", verifyToken, async (req: AuthedRequest, res) => {
  if (req.user?.role !== "tutor") {
    return res.status(403).json({ message: "Only tutors can edit tuitions" });
  }
  const id = req.params.id;
  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ message: "Invalid tuition id" });
  }
  const tuition = await getDb().collection<TuitionDoc>("tuitions").findOne({ _id: new ObjectId(id) });
  if (!tuition) {
    return res.status(404).json({ message: "Tuition not found" });
  }
  if (!tuition.tutorId.equals(req.user!._id)) {
    return res.status(403).json({ message: "You do not own this tuition" });
  }

  const parseResult = tuitionSchema.partial().safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ message: "Invalid tuition update", issues: parseResult.error.issues });
  }
  const update = parseResult.data;

  const result = await getDb()
    .collection<TuitionDoc>("tuitions")
    .updateOne({ _id: new ObjectId(id) }, { $set: update, $currentDate: { updatedAt: true } });
  const refreshed = await getDb().collection<TuitionDoc>("tuitions").findOne({ _id: new ObjectId(id) });
  res.json({ tuition: refreshed });
});

/** Tutor deletes own tuition. */
app.delete("/api/tuitions/:id", verifyToken, async (req: AuthedRequest, res) => {
  if (req.user?.role !== "tutor") {
    return res.status(403).json({ message: "Only tutors can delete tuitions" });
  }
  const id = req.params.id;
  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ message: "Invalid tuition id" });
  }
  const tuition = await getDb().collection<TuitionDoc>("tuitions").findOne({ _id: new ObjectId(id) });
  if (!tuition) {
    return res.status(404).json({ message: "Tuition not found" });
  }
  if (!tuition.tutorId.equals(req.user!._id)) {
    return res.status(403).json({ message: "You do not own this tuition" });
  }
  await getDb().collection<TuitionDoc>("tuitions").deleteOne({ _id: new ObjectId(id) });
  res.json({ message: "Tuition deleted" });
});

/** Admin changes tuition status (approve/reject). */
app.patch("/api/tuitions/:id/status", verifyToken, async (req: AuthedRequest, res) => {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ message: "Only admins can change tuition status" });
  }
  const id = req.params.id;
  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ message: "Invalid tuition id" });
  }
  const statusSchema = z.object({ status: z.enum([TuitionStatus.APPROVED, TuitionStatus.REJECTED]) });
  const parseResult = statusSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ message: "Invalid status", issues: parseResult.error.issues });
  }

  const result = await getDb()
    .collection<TuitionDoc>("tuitions")
    .updateOne({ _id: new ObjectId(id) }, { $set: { status: parseResult.data.status }, $currentDate: { updatedAt: true } });
  const refreshed = await getDb().collection<TuitionDoc>("tuitions").findOne({ _id: new ObjectId(id) });
  res.json({ tuition: refreshed });
});

// ---------------------------------------------------------------------------
// 7. Application APIs
// ---------------------------------------------------------------------------
/** Schema for creating an application. */
const applicationCreateSchema = z.object({
  tuitionId: z.string(),
  message: z.string().optional(),
});

/** Student creates a new application. */
app.post("/api/applications", verifyToken, async (req: AuthedRequest, res) => {
  if (req.user?.role !== "student") {
    return res.status(403).json({ message: "Only students can apply" });
  }

  const parseResult = applicationCreateSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ message: "Invalid application data", issues: parseResult.error.issues });
  }
  const { tuitionId, message } = parseResult.data;
  if (!ObjectId.isValid(tuitionId)) {
    return res.status(400).json({ message: "Invalid tuition id" });
  }
  const tuition = await getDb()
    .collection<TuitionDoc>("tuitions")
    .findOne({ _id: new ObjectId(tuitionId), status: TuitionStatus.APPROVED, active: true });
  if (!tuition) {
    return res.status(404).json({ message: "Tuition not found or not open for applications" });
  }

  // Prevent duplicate applications
  const existing = await getDb()
    .collection<ApplicationDoc>("applications")
    .findOne({ tuitionId: new ObjectId(tuitionId), studentId: req.user!._id });
  if (existing) {
    return res.status(409).json({ message: "Application already exists for this tuition" });
  }

  const appDoc: Partial<ApplicationDoc> = {
    tuitionId: new ObjectId(tuitionId),
    studentId: req.user!._id,
    message,
    status: ApplicationStatus.PENDING,
    createdAt: new Date(),
  };
  const result = await getDb().collection<ApplicationDoc>("applications").insertOne(appDoc as ApplicationDoc);
  const inserted = await getDb().collection<ApplicationDoc>("applications").findOne({ _id: result.insertedId });
  res.status(201).json({ application: inserted });
});

/** Student views own applications. */
app.get("/api/applications/my", verifyToken, async (req: AuthedRequest, res) => {
  if (req.user?.role !== "student") {
    return res.status(403).json({ message: "Only students have a My Applications view" });
  }
  const apps = await getDb()
    .collection<ApplicationDoc>("applications")
    .find({ studentId: req.user!._id })
    .toArray();
  res.json({ applications: apps });
});

/** Tutor views applications for their tuitions. */
app.get("/api/applications/tutor", verifyToken, async (req: AuthedRequest, res) => {
  if (req.user?.role !== "tutor") {
    return res.status(403).json({ message: "Only tutors can view applications to their tuitions" });
  }
  const tutorTuitions = await getDb()
    .collection<TuitionDoc>("tuitions")
    .find({ tutorId: req.user!._id })
    .project({ _id: 1 })
    .toArray();
  const tuitionIds = tutorTuitions.map((t) => t._id);
  const apps = await getDb()
    .collection<ApplicationDoc>("applications")
    .find({ tuitionId: { $in: tuitionIds } })
    .toArray();
  res.json({ applications: apps });
});

/** Tutor updates application status (accept/reject). */
app.patch("/api/applications/:id/status", verifyToken, async (req: AuthedRequest, res) => {
  if (req.user?.role !== "tutor") {
    return res.status(403).json({ message: "Only tutors can change application status" });
  }
  const appId = req.params.id;
  if (!ObjectId.isValid(appId)) {
    return res.status(400).json({ message: "Invalid application id" });
  }
  const statusSchema = z.object({ status: z.enum([ApplicationStatus.ACCEPTED, ApplicationStatus.REJECTED]) });
  const parseResult = statusSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ message: "Invalid status", issues: parseResult.error.issues });
  }

  const application = await getDb()
    .collection<ApplicationDoc>("applications")
    .findOne({ _id: new ObjectId(appId) });
  if (!application) {
    return res.status(404).json({ message: "Application not found" });
  }
  // Verify that the tutor owns the tuition
  const tuition = await getDb()
    .collection<TuitionDoc>("tuitions")
    .findOne({ _id: application.tuitionId });
  if (!tuition || !tuition.tutorId.equals(req.user!._id)) {
    return res.status(403).json({ message: "You do not own this application" });
  }

  await getDb()
    .collection<ApplicationDoc>("applications")
    .updateOne({ _id: new ObjectId(appId) }, { $set: { status: parseResult.data.status }, $currentDate: { updatedAt: true } });
  const refreshed = await getDb().collection<ApplicationDoc>("applications").findOne({ _id: new ObjectId(appId) });
  res.json({ application: refreshed });
});

/** Student cancels (deletes) a pending application. */
app.delete("/api/applications/:id", verifyToken, async (req: AuthedRequest, res) => {
  if (req.user?.role !== "student") {
    return res.status(403).json({ message: "Only students can delete applications" });
  }
  const appId = req.params.id;
  if (!ObjectId.isValid(appId)) {
    return res.status(400).json({ message: "Invalid application id" });
  }
  const application = await getDb()
    .collection<ApplicationDoc>("applications")
    .findOne({ _id: new ObjectId(appId) });
  if (!application) {
    return res.status(404).json({ message: "Application not found" });
  }
  if (!application.studentId.equals(req.user!._id)) {
    return res.status(403).json({ message: "You do not own this application" });
  }
  if (application.status !== ApplicationStatus.PENDING) {
    return res.status(400).json({ message: "Only pending applications can be canceled" });
  }
  await getDb().collection<ApplicationDoc>("applications").deleteOne({ _id: new ObjectId(appId) });
  res.json({ message: "Application canceled" });
});

// ---------------------------------------------------------------------------
// 8. Error handling
// ---------------------------------------------------------------------------
// Unknown routes return JSON instead of the default HTML page.
app.use((req, res) => {
  res.status(404).json({
    message: `Route not found: ${req.method} ${req.originalUrl}`,
  });
});


// ---------------------------------------------------------------------------
// 9. Server startup
// ---------------------------------------------------------------------------
async function startServer(): Promise<void> {
  await connectToDatabase();

  // Create required indexes (runs on each start, safe to call repeatedly)
  const db = getDb();
  // Unique index to prevent duplicate applications per student+tuition
  await db.collection<ApplicationDoc>("applications").createIndex({ tuitionId: 1, studentId: 1 }, { unique: true });
  // Indexes for tuition queries
  await db.collection<TuitionDoc>("tuitions").createIndex({ tutorId: 1 });
  await db.collection<TuitionDoc>("tuitions").createIndex({ status: 1, active: 1 });

  // Initialise BetterAuth after DB is ready.
  authNodeHandler = toNodeHandler(getAuth());

  app.listen(env.port, () => {
    console.log(`[server] MentorLagbe API listening on http://localhost:${env.port}`);
  });
}

startServer().catch((error) => {
  console.error("[server] Failed to start:", error);
  process.exit(1);
});




