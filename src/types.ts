import { ObjectId } from 'mongodb';

/** Core role definitions. */
export type Role = 'student' | 'tutor' | 'admin';

/** User document stored in the `users` collection. */
export interface UserDoc {
  _id: ObjectId;
  email: string;
  name?: string;
  image?: string;
  role: Role;
  phone?: string;
  bio?: string;
  plan: 'free' | 'pro'; // default for new accounts is "free"
  stripeCustomerId?: string;
  /** Tuition _ids (as strings) saved/bookmarked by this student. */
  savedTuitionIds?: string[];
  createdAt: Date;
  updatedAt?: Date;
}

export type User = UserDoc;

/** Legacy tuition status enum – retained for backward compatibility. */
export const TuitionStatus = {
  PENDING: 'pending',
  APPROVED: 'approved',
  REJECTED: 'rejected',
} as const;

export type TuitionStatus = (typeof TuitionStatus)[keyof typeof TuitionStatus];

/** Approval workflow status for a tuition. */
export const TuitionApprovalStatus = {
  PENDING: 'pending',
  APPROVED: 'approved',
  REJECTED: 'rejected',
} as const;

export type TuitionApprovalStatus = (typeof TuitionApprovalStatus)[keyof typeof TuitionApprovalStatus];

/** Tuition document stored in the `tuitions` collection. */
export interface Tuition {
  _id: ObjectId;
  tutorId: ObjectId;

  // Basic information
  title: string;
  description: string;
  subject: string;
  classLevel: string;
  category?: string;

  // Tuition mode and location
  mode: 'online' | 'offline' | 'hybrid';
  location?: string;
  area?: string;

  // Student and tutor preferences
  studentsCount?: number;
  studentGender?: string;
  tutorGender?: string;

  // Schedule information
  daysPerWeek: number;
  preferredDays?: string[];
  preferredTime?: string;

  // Payment information
  monthlyFee: number;
  price?: number;

  // Additional information
  requirements?: string;
  contactNumber?: string;
  bannerImage?: string;

  // Tutor information
  tutorName: string;
  tutorEmail: string;

  // Approval and activity status
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
  PENDING: 'pending',
  ACCEPTED: 'accepted',
  REJECTED: 'rejected',
  APPROVED: 'approved',
} as const;

export type ApplicationStatus = (typeof ApplicationStatus)[keyof typeof ApplicationStatus];

/** Application document stored in the `applications` collection. */

export interface Application {
  _id: ObjectId;
  tuitionId: ObjectId;
  tuitionTitle: string;
  subject: string;
  classLevel?: string;
  monthlyFee: number;

  tutorId?: ObjectId;
  tutorEmail: string;

  studentId: ObjectId;
  studentName: string;
  studentEmail: string;
  studentPhone?: string;

  education?: string;

  preferredSchedule?: string;
  preferredDays?: string[];
  daysPerWeek?: number;
  preferredTime?: string;

  medium?: string;
  academicBackground?: string;

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
  stripeCustomerId?: string;
  stripeCheckoutSessionId?: string;
  stripePaymentIntentId?: string;
  stripeSubscriptionId?: string;
  paymentMethod?: string;
  amount: number;
  currency: string;
  status: 'paid' | 'failed' | 'pending' | 'canceled' | 'refunded';
  paymentType: 'subscription' | 'one_time';
  createdAt: Date;
  updatedAt: Date;

  // Compatibility fields for existing dashboard queries
  userEmail?: string;
  userName?: string;
  userRole?: Role;
  planName?: 'student-pro' | 'tutor-pro';
  transactionId?: string;
  stripeSessionId?: string;
  paymentStatus?: 'paid' | 'failed' | 'pending';
  paidAt?: Date;
}

/** Subscription document stored in the `subscriptions` collection. */
export interface Subscription {
  _id: ObjectId;
  userId: ObjectId;
  userEmail?: string;
  userRole?: Role;
  plan: 'pro' | 'free';
  stripeCustomerId: string;
  stripeSubscriptionId: string;
  stripePriceId?: string;
  status: 'active' | 'canceled' | 'past_due' | 'unpaid' | 'incomplete' | 'trialing';
  currentPeriodStart?: Date;
  currentPeriodEnd?: Date;
  cancelAtPeriodEnd?: boolean;
  createdAt: Date;
  updatedAt: Date;
}

/** Record of processed Stripe webhook events for idempotency. */
export interface ProcessedEvent {
  _id: ObjectId;
  eventId: string;
  type: string;
  processedAt: Date;
}

