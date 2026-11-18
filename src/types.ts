import { ObjectId } from "mongodb";

export type Role = "student" | "tutor" | "admin";

export interface UserDoc {
  _id: ObjectId;
  email: string;
  role: Role;
  plan?: "free" | "pro"; // only for tutors
  name?: string;
  image?: string;
}

export interface User extends UserDoc {}

export enum TuitionStatus {
  PENDING = "pending",
  APPROVED = "approved",
  REJECTED = "rejected",
}

export interface Tuition {
  _id: ObjectId;
  tutorId: ObjectId; // reference to User
  title: string;
  description: string;
  subject: string;
  price: number;
  status: TuitionStatus;
  active: boolean;
  createdAt: Date;
  updatedAt: Date;
}

// Alias for compatibility with previous code expecting TuitionDoc
export type TuitionDoc = Tuition;

export enum ApplicationStatus {
  PENDING = "pending",
  ACCEPTED = "accepted",
  REJECTED = "rejected",
}

export interface Application {
  _id: ObjectId;
  tuitionId: string;
  studentId: ObjectId;
  message?: string;
  status: ApplicationStatus;
  createdAt: Date;
  updatedAt: Date;
}

// Alias for compatibility with previous code expecting ApplicationDoc
export type ApplicationDoc = Application;

export interface Payment {
  _id: ObjectId;
  userId: ObjectId;
  amount: number;
  currency: string;
  status: "pending" | "completed" | "failed";
  createdAt: Date;
  updatedAt: Date;
}
