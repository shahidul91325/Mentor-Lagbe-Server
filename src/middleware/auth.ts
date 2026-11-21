/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * JWT verification and role middlewares.
 *
 * Usage on protected routes:
 *   app.get("/api/x", verifyToken, verifyTutor, handler)
 *
 * Security rules:
 * - the token signature is verified with the server secret
 * - the role is always read from the database, never from the client
 * - invalid/expired tokens and unknown users are rejected with 401
 * - insufficient roles are rejected with 403
 */
import type { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { ObjectId } from "mongodb";
import { env } from "../env.js";
import { getDb } from "../db.js";
import type { Role, User as UserDoc } from "../types.js";

/** Request extended with the authenticated user (set by verifyToken). */
export interface AuthedRequest extends Request {
  user?: UserDoc;
}

/** Verifies `Authorization: Bearer <jwt>` and loads the user from MongoDB. */
export async function verifyToken(
  req: AuthedRequest,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {
      res.status(401).json({ message: "Authentication required. Please sign in." });
      return;
    }

    const decoded = jwt.verify(header.slice(7), env.jwtSecret) as jwt.JwtPayload;

    const sub = decoded.sub || (decoded as any).id;
    if (!sub) {
      res.status(401).json({ message: "Invalid authentication token." });
      return;
    }

    const query = ObjectId.isValid(sub)
      ? { $or: [{ _id: new ObjectId(sub) }, { _id: sub as any }, { id: sub as any }] }
      : { $or: [{ _id: sub as any }, { id: sub as any }] };

    // The role/plan always come from trusted server-side data.
    const user = await getDb()
      .collection<UserDoc>("users")
      .findOne(query);

    if (!user) {
      res.status(401).json({ message: "This account no longer exists." });
      return;
    }

    req.user = user;
    next();
  } catch {
    res.status(401).json({ message: "Invalid or expired token. Please sign in again." });
  }
}

/** Local helper: allows only the given roles (requires verifyToken before it). */
function requireRole(
  req: AuthedRequest,
  res: Response,
  next: NextFunction,
  allowed: Role[],
): void {
  if (!req.user) {
    res.status(401).json({ message: "Authentication required. Please sign in." });
    return;
  }

  if (!allowed.includes(req.user.role)) {
    res.status(403).json({ message: "You do not have permission to access this resource." });
    return;
  }

  next();
}

export function verifyStudent(req: AuthedRequest, res: Response, next: NextFunction): void {
  requireRole(req, res, next, ["student", "admin"]);
}

export function verifyTutor(req: AuthedRequest, res: Response, next: NextFunction): void {
  requireRole(req, res, next, ["tutor", "admin"]);
}

export function verifyAdmin(req: AuthedRequest, res: Response, next: NextFunction): void {
  requireRole(req, res, next, ["admin"]);
}
