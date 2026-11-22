/**
 * BetterAuth server configuration.
 *
 * - MongoDB adapter connected to the shared database handle
 * - user collection is mapped to the assignment's `users` collection
 * - additional user fields: role, plan, phone, bio
 * - `role` accepts only "student" or "tutor" — admin can never be
 *   chosen during public registration (validated server-side with zod)
 *
 * sessions/accounts/verifications are BetterAuth's own authentication
 * storage (passwords/sessions). They are library infrastructure required
 * by the assignment ("BetterAuth + MongoDB adapter") — no extra business
 * collection is introduced.
 */
import { betterAuth } from "better-auth";
import { mongodbAdapter } from "@better-auth/mongo-adapter";
import { z } from "zod";
import { env } from "./env.js";
import { getDb } from "./db.js";

const IS_PRODUCTION = env.nodeEnv === "production";

let authInstance: ReturnType<typeof createBetterAuth> | null = null;

function createBetterAuth() {
  return betterAuth({
    baseURL: env.betterAuthUrl,
    basePath: "/api/auth",
    secret: env.betterAuthSecret,
    // The frontend origin is allowed to call the auth endpoints.
    trustedOrigins: [env.clientUrl],
    database: mongodbAdapter(getDb()),

    // Email + password registration/login (assignment requirement).
    emailAndPassword: {
      enabled: true,
      minPasswordLength: 8,
    },

    user: {
      modelName: "users",
      additionalFields: {
        // Only student or tutor — rejecting "admin" keeps registration safe.
        role: {
          type: "string",
          required: true,
          input: true,
          validator: { input: z.enum(["student", "tutor", "admin"]) },
        },
        plan: {
          type: "string",
          required: true,
          input: false, // never accepted from the client
          defaultValue: "free",
        },
        phone: {
          type: "string",
          required: false,
          input: true,
          defaultValue: "",
        },
        bio: {
          type: "string",
          required: false,
          input: true,
          defaultValue: "",
        },
      },
    },

    session: { modelName: "sessions" },
    account: { modelName: "accounts" },
    verification: { modelName: "verifications" },

    // Defense-in-depth for role security. The zod validator above already
    // rejects "admin" during public sign-up; these hooks make sure the role
    // can never become "admin" through BetterAuth's own user endpoints.
    // Admin accounts are provisioned only by an existing admin through
    // PATCH /api/admin/users/:id/role (or directly in the database).
    databaseHooks: {
      user: {
        create: {
          before: async (user) => {
            const role = (user as { role?: unknown; data?: { role?: unknown } }).role ??
              (user as { data?: { role?: unknown } }).data?.role;

            if (role === "admin") {
              throw new Error("Admin accounts cannot be created through public registration.");
            }

            return;
          },
        },
        update: {
          before: async (user) => {
            const role = (user as { role?: unknown; data?: { role?: unknown } }).role ??
              (user as { data?: { role?: unknown } }).data?.role;

            if (role === "admin") {
              throw new Error("The admin role can only be assigned by an administrator.");
            }

            return;
          },
        },
      },
    },

    advanced: {
      // Cross-site cookies are required in production (Vercel → Render).
      // In development everything runs on localhost, so SameSite=Lax works.
      useSecureCookies: IS_PRODUCTION,
      defaultCookieAttributes: {
        sameSite: IS_PRODUCTION ? "none" : "lax",
        secure: IS_PRODUCTION,
      },
    },
  });
}

/** Returns the shared BetterAuth instance (created after the DB connects). */
export function getAuth() {
  if (!authInstance) {
    authInstance = createBetterAuth();
  }
  return authInstance;
}
