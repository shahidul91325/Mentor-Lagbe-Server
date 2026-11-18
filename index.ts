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
import { env } from "./src/env";
import { connectToDatabase, getDb } from "./src/db";

const IS_PRODUCTION = env.nodeEnv === "production";

// ---------------------------------------------------------------------------
// Section 2: App and middleware setup
// ---------------------------------------------------------------------------
const app = express();

// CORS: only the frontend origin may call this API.
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
// Sections 3–13: Route handlers (added phase by phase)
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

  app.listen(env.port, () => {
    console.log(`[server] MentorLagbe API listening on http://localhost:${env.port}`);
  });
}

startServer().catch((error) => {
  console.error("[server] Failed to start:", error);
  process.exit(1);
});
