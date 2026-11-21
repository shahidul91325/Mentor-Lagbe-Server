// src/types.ts
import { ObjectId } from "mongodb";

/** Core role definitions. */
export type Role = "student" | "tutor" | "admin";

/** User document stored in the `users` collection. */
export interface UserDoc {
  _id: ObjectId;
  email: string;
  name?: string;
  image?: string;
  role: Role;
  phone?: string;
  bio?: string;
  plan: "free" | "pro"; // default for new accounts is "free"
  createdAt: Date;
}

export type User = UserDoc;

/** Legacy tuition status enum – retained for backward compatibility. */
export const TuitionStatus = {
  PENDING: "pending",
  APPROVED: "approved",
  REJECTED: "rejected",
} as const;
export type TuitionStatus = (typeof TuitionStatus)[keyof typeof TuitionStatus];

/** Approval workflow status for a tuition. */
export const TuitionApprovalStatus = {
  PENDING: "pending",
  APPROVED: "approved",
  REJECTED: "rejected",
} as const;
export type TuitionApprovalStatus = (typeof TuitionApprovalStatus)[keyof typeof TuitionApprovalStatus];

/** Tuition document stored in the `tuitions` collection. */
export interface Tuition {
  _id: ObjectId;
  tutorId: ObjectId; // reference to a User
  title: string;
  subject: string;
  classLevel: string;
  mode: "online" | "offline" | "hybrid";
  location?: string;
  monthlyFee: number;
  price?: number;
  daysPerWeek: number;
  bannerImage?: string;
  description: string;
  tutorName: string;
  tutorEmail: string;
  approvalStatus: TuitionApprovalStatus;
  status?: TuitionStatus;
  isActive: boolean;
  active?: boolean;
  createdAt: Date;
  updatedAt?: Date;
}

/** Alias for compatibility with existing code that expects `TuitionDoc`. */
export type TuitionDoc = Tuition;

/** Application status enumeration. */
export const ApplicationStatus = {
  PENDING: "pending",
  ACCEPTED: "accepted",
  REJECTED: "rejected",
} as const;
export type ApplicationStatus = (typeof ApplicationStatus)[keyof typeof ApplicationStatus];

/** Application document stored in the `applications` collection. */
export interface Application {
  _id: ObjectId;
  tuitionId: ObjectId;
  tuitionTitle: string;
  subject: string;
  monthlyFee: number;
  tutorEmail: string;
  studentId: ObjectId;
  studentName: string;
  studentEmail: string;
  studentPhone?: string;
  preferredSchedule?: string;
  studentNote?: string;
  message?: string;
  status: ApplicationStatus;
  appliedAt: Date;
  createdAt?: Date;
  updatedAt?: Date;
}

/** Alias for compatibility with existing code that expects `ApplicationDoc`. */
export type ApplicationDoc = Application;

/** Payment document stored in the `payments` collection. */
export interface Payment {
  _id: ObjectId;
  userId: ObjectId;
  userEmail: string;
  userName: string;
  userRole: Role;
  planName: "student-pro" | "tutor-pro";
  amount: number;
  currency: string;
  transactionId: string;
  stripeSessionId: string;
  paymentStatus: "paid" | "failed" | "pending";
  paidAt: Date;
}
