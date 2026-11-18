/**
 * Shared TypeScript types for the MentorLagbe server.
 * Mirrors the four assignment collections (only `users` is referenced here
 * for now — tuitions/applications/payments handlers arrive in later phases).
 */
import type { ObjectId } from "mongodb";

export type Role = "student" | "tutor" | "admin";
export type Plan = "free" | "pro";

/** Document shape of the `users` collection. */
export interface UserDoc {
  _id: ObjectId;
  name: string;
  email: string;
  image?: string;
  role: Role;
  phone?: string;
  bio?: string;
  plan: Plan;
  createdAt: Date;
  updatedAt?: Date;
}
