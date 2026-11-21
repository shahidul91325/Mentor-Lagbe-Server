import jwt from "jsonwebtoken";
import { ObjectId } from "mongodb";
import { env } from "../env.js";
import { getDb } from "../db.js";
/** Verifies `Authorization: Bearer <jwt>` and loads the user from MongoDB. */
export async function verifyToken(req, res, next) {
    try {
        const header = req.headers.authorization;
        if (!header || !header.startsWith("Bearer ")) {
            res.status(401).json({ message: "Authentication required. Please sign in." });
            return;
        }
        const decoded = jwt.verify(header.slice(7), env.jwtSecret);
        if (!decoded.sub || !ObjectId.isValid(decoded.sub)) {
            res.status(401).json({ message: "Invalid authentication token." });
            return;
        }
        // The role/plan always come from trusted server-side data.
        const user = await getDb()
            .collection("users")
            .findOne({ _id: new ObjectId(decoded.sub) });
        if (!user) {
            res.status(401).json({ message: "This account no longer exists." });
            return;
        }
        req.user = user;
        next();
    }
    catch {
        res.status(401).json({ message: "Invalid or expired token. Please sign in again." });
    }
}
/** Local helper: allows only the given roles (requires verifyToken before it). */
function requireRole(req, res, next, allowed) {
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
export function verifyStudent(req, res, next) {
    requireRole(req, res, next, ["student"]);
}
export function verifyTutor(req, res, next) {
    requireRole(req, res, next, ["tutor"]);
}
export function verifyAdmin(req, res, next) {
    requireRole(req, res, next, ["admin"]);
}
