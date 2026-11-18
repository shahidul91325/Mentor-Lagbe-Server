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
 *   3. Database connection
 *   4. BetterAuth integration
 *   5. Shared validation/helpers
 *   6. Public tuition APIs
 *   7. Student APIs
 *   8. Tutor APIs
 *   9. Admin APIs
 *   10. Profile APIs
 *   11. ImgBB upload API
 *   12. Stripe Checkout APIs
 *   13. Stripe Webhook
 *   14. Error handling
 *   15. Server startup
 * ==========================================================================*/

// ---------------------------------------------------------------------------
// Section 1: Imports and configuration
// ---------------------------------------------------------------------------
import express, { type ErrorRequestHandler } from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import { fromNodeHeaders, toNodeHandler } from "better-auth/node";
import { env } from "./src/env";
import { connectToDatabase, getDb } from "./src/db";
import { getAuth } from "./src/better-auth";
import { verifyToken, type AuthedRequest } from "./src/middleware/auth";

const IS_PRODUCTION = env.nodeEnv === "production";

// ---------------------------------------------------------------------------
// Section 2: App and middleware setup
// ---------------------------------------------------------------------------
const app = express();

// CORS: only the frontend origin may call this API (cookies included).
app.use(
  cors({
    origin: env.clientUrl,
    credentials: true,
  }),
);

// Stripe webhook needs the raw request body, so it will be mounted with
// express.raw() BEFORE express.json() (see Section 13 — Stripe Webhook).

// Parse JSON request bodies.
app.use(express.json());

// ---------------------------------------------------------------------------
// Sections 5–13: Route handlers (added phase by phase)
// ---------------------------------------------------------------------------

/**
 * Health check — verifies that the API and MongoDB are reachable.
 * Used to confirm deployment is alive.
 */
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
// Section 4: BetterAuth integration
// ---------------------------------------------------------------------------

/**
 * Mints a MentorLagbe JWT for the current BetterAuth session.
 * The frontend calls this right after sign-up/sign-in and stores the token,
 * which is then sent as `Authorization: Bearer <token>` on protected APIs.
 */
app.post("/api/auth/token", async (req, res) => {
  const session = await getAuth().api.getSession({ headers: fromNodeHeaders(req.headers) });

  if (!session) {
    res.status(401).json({ message: "No active session. Please sign in first." });
    return;
  }

  const token = jwt.sign({ sub: session.user.id }, env.jwtSecret, { expiresIn: "7d" });

  res.json({ token });
});

/** Node adapter handler for every BetterAuth route (sign-up, sign-in, session…). */
let authNodeHandler: ReturnType<typeof toNodeHandler> | null = null;

// Express 5 wildcard syntax: /api/auth/{*splat}
// (path-to-regexp v8 no longer accepts a bare "*")
app.all("/api/auth/{*splat}", (req, res) => {
  if (!authNodeHandler) {
    res.status(503).json({ message: "Authentication service is not ready yet" });
    return;
  }
  return authNodeHandler(req, res);
});

// ---------------------------------------------------------------------------
// Section 10: Profile APIs
// ---------------------------------------------------------------------------

/** Returns the signed-in user's profile (from trusted server-side data). */
app.get("/api/users/me", verifyToken, (req: AuthedRequest, res) => {
  res.json({ user: req.user });
});

// ---------------------------------------------------------------------------
// Section 14: Error handling
// ---------------------------------------------------------------------------

// Unknown routes return JSON instead of the default HTML page.
app.use((req, res) => {
  res.status(404).json({
    message: `Route not found: ${req.method} ${req.originalUrl}`,
  });
});

// Central error handler — keeps error responses consistent.
const errorHandler: ErrorRequestHandler = (error, _req, res, _next) => {
  console.error("[error]", error);

  res.status(500).json({
    message: "Something went wrong on the server",
    ...(IS_PRODUCTION ? {} : { error: error instanceof Error ? error.message : String(error) }),
  });
};

app.use(errorHandler);

// ---------------------------------------------------------------------------
// Section 15: Server startup
// ---------------------------------------------------------------------------
async function startServer(): Promise<void> {
  await connectToDatabase();

  // BetterAuth can only be created once the database handle exists.
  authNodeHandler = toNodeHandler(getAuth());

  app.listen(env.port, () => {
    console.log(`[server] MentorLagbe API listening on http://localhost:${env.port}`);
  });
}

startServer().catch((error) => {
  console.error("[server] Failed to start:", error);
  process.exit(1);
});
