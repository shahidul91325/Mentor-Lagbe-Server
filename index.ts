/* eslint-disable @typescript-eslint/no-explicit-any */
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
 *   4. BetterAuth integration
 *   5. Profile APIs
 *   6. Admin Tuition Management
 *   7. Admin User Management
 *   8. Tuition APIs
 *   9. Application APIs
 *  10. Dashboard APIs
 *  11. 404 & Error handling
 *  12. Server startup & shutdown handling
 * ==========================================================================*/

// ---------------------------------------------------------------------------
// 1. Imports and configuration
// ---------------------------------------------------------------------------
import express, { type ErrorRequestHandler } from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { fromNodeHeaders, toNodeHandler } from 'better-auth/node';
import Stripe from 'stripe';
import { env } from './src/env.js';
import { connectToDatabase, getDb } from './src/db.js';
import { getAuth } from './src/better-auth.js';
import { verifyToken, type AuthedRequest } from './src/middleware/auth.js';
import { z } from 'zod';
import {
  type UserDoc,
  type TuitionDoc,
  type ApplicationDoc,
  type Role,
  ApplicationStatus,
  TuitionStatus,
  TuitionApprovalStatus,
  type Payment,
  type Subscription,
  type ProcessedEvent,
} from './src/types.js';
import { Db, ObjectId } from 'mongodb';

const IS_PRODUCTION = env.nodeEnv === 'production';
const stripe = env.stripeSecretKey ? new Stripe(env.stripeSecretKey) : null;

// ---------------------------------------------------------------------------
// 2. App and middleware setup
// ---------------------------------------------------------------------------
const app = express();

app.use(
  cors({
    origin: env.clientUrl,
    credentials: true,
  })
);

// Stripe webhook requires raw body for cryptographic signature verification.
// Must be registered before express.json().
app.use('/api/payments/webhook', express.raw({ type: 'application/json' }));

// Image uploads travel as base64 JSON, so this route needs a larger body limit
// than the default 100kb. Registered before the global JSON parser; body-parser
// marks the request as parsed so the global parser skips it afterwards.
app.use('/api/upload/image', express.json({ limit: '8mb' }));

app.use(
  express.json({
    verify: (req, _res, buf) => {
      (req as any).rawBody = buf;
    },
  })
);
app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------------------------
// 3. Health check
// ---------------------------------------------------------------------------
// Ensure database connectivity before any route handler runs (Vercel serverless safe).
app.use(async (_req, res, next) => {
  try {
    await connectToDatabase();
    if (!authNodeHandler) {
      authNodeHandler = toNodeHandler(getAuth());
    }
    next();
  } catch (error) {
    next(error);
  }
});

app.get('/api/health', async (_req, res, next) => {
  try {
    await getDb().command({ ping: 1 });

    res.json({
      status: 'ok',
      message: 'MentorLagbe API is running',
      database: 'connected',
      environment: env.nodeEnv,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// 4. BetterAuth integration (token minting & route forwarding)
// ---------------------------------------------------------------------------
/**
 * Handles JWT token minting and retrieval for both GET and POST requests.
 * Authenticates via BetterAuth session cookies/headers or existing valid Bearer token.
 */
const handleAuthToken = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
  try {
    let userId: string | null = null;
    const cookieHeader = req.headers.cookie || '';
    const hasCookie = !!cookieHeader;

    // Log incoming request details for diagnostics (no sensitive data)
    console.info('[auth/token] Request received', {
      method: req.method,
      hasCookie,
      cookieLength: cookieHeader.length,
      cookieNames: cookieHeader.split(';').map(c => c.trim().split('=')[0]),
      hasAuthHeader: !!req.headers.authorization,
      userAgent: req.headers['user-agent']?.substring(0, 50),
    });

    // 1. Try BetterAuth session using standard header conversion
    // This preserves all cookies including session cookies for cross-origin requests
    try {
      const session = await getAuth().api.getSession({
        headers: fromNodeHeaders(req.headers),
      });

      if (session?.user?.id) {
        userId = session.user.id;
        console.info('[auth/token] Session validated via fromNodeHeaders', { userId });
      } else {
        console.debug('[auth/token] fromNodeHeaders returned no session');
      }
    } catch (err) {
      console.debug('[auth/token] getSession via fromNodeHeaders failed:', err instanceof Error ? err.message : 'unknown error');
    }

    // 2. Fallback: pass the complete original Cookie header to BetterAuth
    // This handles cases where fromNodeHeaders doesn't properly forward cookies in serverless environments
    if (!userId && hasCookie) {
      try {
        const headers = new Headers();
        headers.set('cookie', cookieHeader);
        const session = await getAuth().api.getSession({ headers });
        if (session?.user?.id) {
          userId = session.user.id;
          console.info('[auth/token] Session validated via full Cookie header fallback', { userId });
        } else {
          console.debug('[auth/token] Full Cookie header fallback returned no session');
        }
      } catch (err) {
        console.debug('[auth/token] getSession via full Cookie header failed:', err instanceof Error ? err.message : 'unknown error');
      }
    }

    // 3. If no BetterAuth session, check Authorization: Bearer <token>
    // Only used as last resort for API clients that use JWT directly
    if (!userId && req.headers.authorization?.startsWith('Bearer ')) {
      const rawToken = req.headers.authorization.slice(7);
      try {
        const decoded = jwt.verify(rawToken, env.jwtSecret) as jwt.JwtPayload;
        const sub = decoded.sub || (decoded as any).id;
        if (sub) {
          userId = String(sub);
          console.info('[auth/token] User authenticated via Bearer JWT fallback', { userId });
        }
      } catch (err) {
        console.debug('[auth/token] Bearer JWT verification failed:', err instanceof Error ? err.message : 'unknown error');
      }
    }

    if (!userId) {
      console.warn('[auth/token] No valid session found', {
        hasCookie,
        cookieNames: cookieHeader.split(';').map(c => c.trim().split('=')[0]),
        triedFromNodeHeaders: true,
        triedFullCookieHeader: hasCookie,
        triedBearerToken: !!req.headers.authorization?.startsWith('Bearer '),
      });
      res.status(401).json({
        message: 'No active session. Please sign in first.',
      });
      return;
    }

    const db = getDb();
    const query = ObjectId.isValid(userId)
      ? { $or: [{ _id: new ObjectId(userId) }, { _id: userId as any }, { id: userId }] }
      : { $or: [{ _id: userId as any }, { id: userId }] };

    const user = await db.collection<UserDoc>('users').findOne(query);

    if (!user) {
      console.warn('[auth/token] User not found in database for userId:', userId);
      res.status(401).json({
        message: 'This account no longer exists.',
      });
      return;
    }

    console.info('[auth/token] JWT minted successfully', { userId: user._id.toString(), role: user.role });

    const payload = {
      sub: user._id.toString(),
      id: user._id.toString(),
      email: user.email,
      role: user.role,
      name: user.name,
    };

    const token = jwt.sign(payload, env.jwtSecret, { expiresIn: '7d' });

    res.json({
      token,
      user: {
        _id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role,
        plan: user.plan || 'free',
      },
    });
  } catch (error) {
    next(error);
  }
};

app.get('/api/auth/token', handleAuthToken);
app.post('/api/auth/token', handleAuthToken);

let authNodeHandler: ReturnType<typeof toNodeHandler> | null = null;

app.use('/api/auth', (req, res) => {
  if (!authNodeHandler) {
    res.status(503).json({
      message: 'Authentication service is not ready yet',
    });
    return;
  }

  // Diagnostic logging for BetterAuth routes
  console.info('[better-auth] Request received', {
    method: req.method,
    path: req.path,
    hasCookie: !!req.headers.cookie,
    cookieNames: (req.headers.cookie || '').split(';').map(c => c.trim().split('=')[0]),
  });

  return authNodeHandler(req, res);
});

// ---------------------------------------------------------------------------
// 5. Profile APIs
// ---------------------------------------------------------------------------
app.get('/api/users/me', verifyToken, (req: AuthedRequest, res) => {
  if (!req.user) {
    res.status(401).json({
      message: 'Authentication required. Please sign in.',
    });
    return;
  }

  res.json({ user: req.user });
});

app.patch('/api/users/me', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user) {
      res.status(401).json({
        message: 'Authentication required. Please sign in.',
      });
      return;
    }

    const schema = z
      .object({
        name: z.string().optional(),
        phone: z.string().optional(),
        bio: z.string().optional(),
        image: z.string().optional(),
      })
      .strict();

    const parseResult = schema.safeParse(req.body);

    if (!parseResult.success) {
      res.status(400).json({
        message: 'Invalid profile data',
        issues: parseResult.error.issues,
      });
      return;
    }

    const update = parseResult.data;
    const rawBody = req.body as Record<string, unknown>;

    if (rawBody.role !== undefined || rawBody.plan !== undefined) {
      res.status(400).json({
        message: 'Cannot change role or plan via profile update',
      });
      return;
    }

    const result = await getDb()
      .collection<UserDoc>('users')
      .updateOne({ _id: req.user._id }, { $set: update, $currentDate: { updatedAt: true } });

    if (result.matchedCount === 0) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    const refreshed = await getDb().collection<UserDoc>('users').findOne({ _id: req.user._id });

    res.json({ user: refreshed });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// 6. Admin Tuition Management
// ---------------------------------------------------------------------------
app.get('/api/admin/tuitions', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (req.user?.role !== 'admin') {
      res.status(403).json({ message: 'Admin access required' });
      return;
    }

    const {
      status,
      search,
      page = '1',
      limit = '20',
      sortBy = 'createdAt',
      sortOrder = 'desc',
    } = req.query as Record<string, string | undefined>;

    const filter: Record<string, unknown> = {};

    if (status) {
      filter.$or = [{ approvalStatus: status }, { status }];
    }

    if (search) {
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter.title = { $regex: new RegExp(escaped, 'i') };
    }

    const pageNum = Math.max(parseInt(page || '1', 10) || 1, 1);
    const limitNum = Math.min(Math.max(parseInt(limit || '20', 10) || 20, 1), 100);
    const skip = (pageNum - 1) * limitNum;

    const validSortFields = ['createdAt', 'monthlyFee', 'price', 'title', 'subject'];

    const sortField = validSortFields.includes(sortBy || '') ? sortBy! : 'createdAt';

    const sort: Record<string, 1 | -1> = {};
    sort[sortField] = sortOrder === 'asc' ? 1 : -1;

    const cursor = getDb().collection<TuitionDoc>('tuitions').find(filter).sort(sort).skip(skip).limit(limitNum);

    const tuitions = await cursor.toArray();
    const total = await getDb().collection<TuitionDoc>('tuitions').countDocuments(filter);

    const totalPages = Math.ceil(total / limitNum) || 1;

    res.json({
      tuitions,
      total,
      page: pageNum,
      limit: limitNum,
      totalPages,
    });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/admin/tuitions/:id/approve', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (req.user?.role !== 'admin') {
      res.status(403).json({ message: 'Admin access required' });
      return;
    }

    const id = req.params.id;

    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid tuition id' });
      return;
    }

    const tuition = await getDb()
      .collection<TuitionDoc>('tuitions')
      .findOne({ _id: new ObjectId(id) });

    if (!tuition) {
      res.status(404).json({ message: 'Tuition not found' });
      return;
    }

    if (tuition.approvalStatus !== TuitionApprovalStatus.PENDING && tuition.status !== TuitionStatus.PENDING) {
      res.status(400).json({
        message: 'Only pending tuitions can be approved',
      });
      return;
    }

    await getDb()
      .collection<TuitionDoc>('tuitions')
      .updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            approvalStatus: TuitionApprovalStatus.APPROVED,
            status: TuitionStatus.APPROVED,
          },
          $currentDate: { updatedAt: true },
        }
      );

    const refreshed = await getDb()
      .collection<TuitionDoc>('tuitions')
      .findOne({ _id: new ObjectId(id) });

    res.json({ tuition: refreshed });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/admin/tuitions/:id/reject', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (req.user?.role !== 'admin') {
      res.status(403).json({ message: 'Admin access required' });
      return;
    }

    const id = req.params.id;

    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid tuition id' });
      return;
    }

    const tuition = await getDb()
      .collection<TuitionDoc>('tuitions')
      .findOne({ _id: new ObjectId(id) });

    if (!tuition) {
      res.status(404).json({ message: 'Tuition not found' });
      return;
    }

    if (tuition.approvalStatus !== TuitionApprovalStatus.PENDING && tuition.status !== TuitionStatus.PENDING) {
      res.status(400).json({
        message: 'Only pending tuitions can be rejected',
      });
      return;
    }

    await getDb()
      .collection<TuitionDoc>('tuitions')
      .updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            approvalStatus: TuitionApprovalStatus.REJECTED,
            status: TuitionStatus.REJECTED,
          },
          $currentDate: { updatedAt: true },
        }
      );

    const refreshed = await getDb()
      .collection<TuitionDoc>('tuitions')
      .findOne({ _id: new ObjectId(id) });

    res.json({ tuition: refreshed });
  } catch (error) {
    next(error);
  }
});

app.get('/api/admin/tuitions/:id', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (req.user?.role !== 'admin') {
      res.status(403).json({ message: 'Admin access required' });
      return;
    }

    const id = req.params.id;

    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid tuition id' });
      return;
    }

    const tuition = await getDb()
      .collection<TuitionDoc>('tuitions')
      .findOne({ _id: new ObjectId(id) });

    if (!tuition) {
      res.status(404).json({ message: 'Tuition not found' });
      return;
    }

    res.json({ tuition });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// 7. Admin User Management
// ---------------------------------------------------------------------------
app.get('/api/admin/users', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (req.user?.role !== 'admin') {
      res.status(403).json({ message: 'Admin access required' });
      return;
    }

    const {
      role,
      search,
      page = '1',
      limit = '20',
      sortBy = 'createdAt',
      sortOrder = 'desc',
    } = req.query as Record<string, string | undefined>;

    const filter: Record<string, unknown> = {};

    if (role) filter.role = role;

    if (search) {
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(escaped, 'i');

      filter.$or = [{ email: { $regex: regex } }, { name: { $regex: regex } }];
    }

    const pageNum = Math.max(parseInt(page || '1', 10) || 1, 1);
    const limitNum = Math.min(Math.max(parseInt(limit || '20', 10) || 20, 1), 100);
    const skip = (pageNum - 1) * limitNum;

    const validSortFields = ['createdAt', 'email', 'name', 'role'];
    const sortField = validSortFields.includes(sortBy || '') ? sortBy! : 'createdAt';

    const sort: Record<string, 1 | -1> = {};
    sort[sortField] = sortOrder === 'asc' ? 1 : -1;

    const cursor = getDb().collection<UserDoc>('users').find(filter).sort(sort).skip(skip).limit(limitNum);

    const users = await cursor.toArray();
    const total = await getDb().collection<UserDoc>('users').countDocuments(filter);

    const totalPages = Math.ceil(total / limitNum) || 1;

    res.json({
      users,
      total,
      page: pageNum,
      limit: limitNum,
      totalPages,
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/admin/users/:id', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (req.user?.role !== 'admin') {
      res.status(403).json({ message: 'Admin access required' });
      return;
    }

    const id = req.params.id;

    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid user id' });
      return;
    }

    const user = await getDb()
      .collection<UserDoc>('users')
      .findOne({ _id: new ObjectId(id) });

    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    res.json({ user });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/admin/users/:id/role', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (req.user?.role !== 'admin') {
      res.status(403).json({ message: 'Admin access required' });
      return;
    }

    const id = req.params.id;

    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid user id' });
      return;
    }

    const schema = z.object({
      role: z.enum(['student', 'tutor', 'admin']),
    });

    const parseResult = schema.safeParse(req.body);

    if (!parseResult.success) {
      res.status(400).json({
        message: 'Invalid role payload',
        issues: parseResult.error.issues,
      });
      return;
    }

    const newRole = parseResult.data.role;

    if (req.user._id.equals(new ObjectId(id)) && newRole !== 'admin') {
      res.status(400).json({
        message: 'Admins cannot demote themselves',
      });
      return;
    }

    if (newRole !== 'admin') {
      const adminCount = await getDb().collection<UserDoc>('users').countDocuments({ role: 'admin' });

      const targetUser = await getDb()
        .collection<UserDoc>('users')
        .findOne({ _id: new ObjectId(id) });

      if (targetUser?.role === 'admin' && adminCount <= 1) {
        res.status(400).json({
          message: 'Cannot remove the last admin',
        });
        return;
      }
    }

    await getDb()
      .collection<UserDoc>('users')
      .updateOne(
        { _id: new ObjectId(id) },
        {
          $set: { role: newRole },
          $currentDate: { updatedAt: true },
        }
      );

    const updated = await getDb()
      .collection<UserDoc>('users')
      .findOne({ _id: new ObjectId(id) });

    res.json({ user: updated });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// 8. Tuition APIs (public, tutor & admin)
// ---------------------------------------------------------------------------

/**
 * Tuition creation schema.
 * Includes all fields submitted by the Post Tuition form.
 */
const tuitionSchema = z
  .object({
    title: z.string().min(1, 'Title is required'),
    description: z.string().min(1, 'Description is required'),

    subject: z.string().optional().default('General'),
    classLevel: z.string().optional().default('All Levels'),

    category: z.string().optional().default(''),

    mode: z.enum(['online', 'offline', 'hybrid']).optional().default('online'),

    location: z.string().optional(),
    area: z.string().optional().default(''),

    monthlyFee: z.number().nonnegative().optional(),
    price: z.number().nonnegative().optional(),

    daysPerWeek: z.number().int().positive().optional().default(3),
    preferredDays: z.array(z.string()).optional().default([]),
    preferredTime: z.string().optional().default(''),

    studentsCount: z.number().int().min(1).optional().default(1),

    studentGender: z.string().optional().default('Any'),
    tutorGender: z.string().optional().default('Any'),

    requirements: z.string().optional().default(''),
    contactNumber: z.string().optional().default(''),

    bannerImage: z.string().optional().default(''),

    active: z.boolean().optional(),
  })
  .refine((data) => data.monthlyFee !== undefined || data.price !== undefined, {
    message: 'Either monthlyFee or price must be provided',
  });

/** Get public list of approved and active tuitions. */
app.get('/api/tuitions', async (req, res, next) => {
  try {
    const querySchema = z.object({
      search: z.string().optional(),
      subject: z.string().optional(),
      classLevel: z.string().optional(),
      mode: z.enum(['online', 'offline', 'hybrid']).optional(),
      location: z.string().optional(),
      minFee: z.coerce.number().nonnegative().optional(),
      maxFee: z.coerce.number().nonnegative().optional(),
      page: z.coerce.number().int().positive().optional().default(1),
      limit: z.coerce.number().int().positive().optional().default(10),
      sortBy: z.enum(['monthlyFee', 'price', 'createdAt', 'title']).optional().default('createdAt'),
      sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
    });

    const parseResult = querySchema.safeParse(req.query);

    if (!parseResult.success) {
      res.status(400).json({
        message: 'Invalid query parameters',
        issues: parseResult.error.issues,
      });
      return;
    }

    const { search, subject, classLevel, mode, location, minFee, maxFee, page, limit, sortBy, sortOrder } =
      parseResult.data;

    const filter: Record<string, unknown> = {
      $or: [{ approvalStatus: TuitionApprovalStatus.APPROVED }, { status: TuitionStatus.APPROVED }],
      $and: [
        {
          $or: [{ isActive: true }, { active: true }],
        },
      ],
    };

    if (search) {
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter.title = { $regex: new RegExp(escaped, 'i') };
    }

    if (subject) filter.subject = subject;
    if (classLevel) filter.classLevel = classLevel;
    if (mode) filter.mode = mode;
    if (location) filter.location = location;

    if (minFee !== undefined || maxFee !== undefined) {
      const feeFilter: Record<string, number> = {};

      if (minFee !== undefined) feeFilter.$gte = minFee;
      if (maxFee !== undefined) feeFilter.$lte = maxFee;

      filter.$or = [{ monthlyFee: feeFilter }, { price: feeFilter }];
    }

    const collection = getDb().collection<TuitionDoc>('tuitions');

    const total = await collection.countDocuments(filter);
    const skip = (page - 1) * limit;

    const sortField = sortBy === 'price' ? 'monthlyFee' : sortBy;
    const sort: Record<string, 1 | -1> = {};

    sort[sortField] = sortOrder === 'asc' ? 1 : -1;

    const tuitions = await collection.find(filter).sort(sort).skip(skip).limit(limit).toArray();

    // Enrich each tuition with basic tutor info (name, email, image) so public
    // cards can show the tutor without a separate request per tuition.
    const tutorIds = [...new Set(tuitions.map((t) => t.tutorId).filter(Boolean))];
    let tutorMap = new Map<string, { name?: string | null; email?: string | null; image?: string | null }>();
    if (tutorIds.length > 0) {
      const tutors = await getDb()
        .collection<UserDoc>('users')
        .find({ _id: { $in: tutorIds } })
        .project({ name: 1, email: 1, image: 1 })
        .toArray();
      tutorMap = new Map(tutors.map((t) => [t._id.toString(), { name: t.name, email: t.email, image: t.image }]));
    }

    const enrichedTuitions = tuitions.map((t) => {
      const tutorId = t.tutorId ? t.tutorId.toString() : '';
      const tutor = tutorMap.get(tutorId);
      return {
        ...t,
        tutor: {
          _id: tutorId,
          name: tutor?.name || t.tutorName || 'Tutor',
          email: tutor?.email || t.tutorEmail,
          image: tutor?.image,
        },
      };
    });

    const totalPages = Math.ceil(total / limit) || 1;

    res.json({
      tuitions: enrichedTuitions,
      total,
      page,
      limit,
      totalPages,
    });
  } catch (error) {
    next(error);
  }
});

/** Tutor view own tuitions, including pending and rejected. */
app.get('/api/tuitions/my', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user || req.user.role !== 'tutor') {
      res.status(403).json({ message: 'Tutor access required' });
      return;
    }

    const tuitions = await getDb().collection<TuitionDoc>('tuitions').find({ tutorId: req.user._id }).toArray();

    res.json({ tuitions });
  } catch (error) {
    next(error);
  }
});

/** Get a single tuition with all saved fields and tutor details. */
/** Student lists their saved (bookmarked) tuitions. */
app.get('/api/tuitions/bookmarks/saved', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user || req.user.role !== 'student') {
      res.status(403).json({ message: 'Only students can view saved tuitions' });
      return;
    }

    const userId = req.user._id;

    const user = await getDb()
      .collection<UserDoc>('users')
      .findOne({ _id: userId });

    const savedIds: string[] = user?.savedTuitionIds ?? [];

    // Clean up references to tuitions that no longer exist, so a student's
    // saved list never contains dangling ids.
    const validIds = savedIds.filter((id) => ObjectId.isValid(id));

    let tuitions: TuitionDoc[] = [];
    if (validIds.length > 0) {
      tuitions = await getDb()
        .collection<TuitionDoc>('tuitions')
        .find({ _id: { $in: validIds.map((id) => new ObjectId(id)) } })
        .sort({ createdAt: -1 })
        .toArray();
    }

    const existingIds = new Set(tuitions.map((t) => t._id.toString()));
    const cleanedIds = savedIds.filter((id) => existingIds.has(id));

    if (cleanedIds.length !== savedIds.length) {
      await getDb()
        .collection<UserDoc>('users')
        .updateOne({ _id: userId }, { $set: { savedTuitionIds: cleanedIds }, $currentDate: { updatedAt: true } });
    }

    // Enrich with tutor information (mirrors the single-tuition detail endpoint).
    const tutorIds = [...new Set(tuitions.map((t) => t.tutorId).filter(Boolean))];
    const tutors = await getDb()
      .collection<UserDoc>('users')
      .find({ _id: { $in: tutorIds.map((id) => new ObjectId(id.toString())) } })
      .toArray();
    const tutorMap = new Map(
      tutors.map((t) => [t._id.toString(), { _id: t._id.toString(), name: t.name, email: t.email, image: t.image }])
    );

    const savedTuitions = tuitions.map((t) => ({
      ...t,
      tutor: {
        _id: t.tutorId?.toString() ?? '',
        name: tutorMap.get(t.tutorId?.toString() ?? '')?.name || t.tutorName || 'Tutor',
        email: tutorMap.get(t.tutorId?.toString() ?? '')?.email || t.tutorEmail,
        image: tutorMap.get(t.tutorId?.toString() ?? '')?.image,
      },
    }));

    res.json({
      savedTuitions,
      total: savedTuitions.length,
      savedTuitionIds: cleanedIds,
      limit: BOOKMARK_FREE_LIMIT,
      plan: req.user.plan,
      unlimited: req.user.plan === 'pro',
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/tuitions/:id', async (req, res, next) => {
  try {
    const id = req.params.id;

    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid tuition id' });
      return;
    }

    const tuition = await getDb()
      .collection<TuitionDoc>('tuitions')
      .findOne({ _id: new ObjectId(id) });

    if (!tuition) {
      res.status(404).json({ message: 'Tuition not found' });
      return;
    }

    const isApproved =
      tuition.approvalStatus === TuitionApprovalStatus.APPROVED || tuition.status === TuitionStatus.APPROVED;

    const isActive = tuition.isActive === true || tuition.active === true;

    if (!isApproved || !isActive) {
      let canView = false;
      const header = req.headers.authorization;

      if (header && header.startsWith('Bearer ')) {
        try {
          const decoded = jwt.verify(header.slice(7), env.jwtSecret) as jwt.JwtPayload;

          if (decoded.sub && ObjectId.isValid(decoded.sub)) {
            const caller = await getDb()
              .collection<UserDoc>('users')
              .findOne({ _id: new ObjectId(decoded.sub) });

            if (
              caller &&
              (caller.role === 'admin' ||
                (tuition.tutorId && new ObjectId(tuition.tutorId).equals(caller._id)) ||
                tuition.tutorEmail === caller.email)
            ) {
              canView = true;
            }
          }
        } catch {
          // Invalid token; access remains denied.
        }
      }

      if (!canView) {
        res.status(404).json({ message: 'Tuition not found' });
        return;
      }
    }

    const tutorUser = tuition.tutorId
      ? await getDb()
          .collection<UserDoc>('users')
          .findOne(
            { _id: new ObjectId(tuition.tutorId) },
            {
              projection: {
                name: 1,
                email: 1,
                image: 1,
                phone: 1,
                bio: 1,
                role: 1,
              },
            }
          )
      : await getDb()
          .collection<UserDoc>('users')
          .findOne(
            { email: tuition.tutorEmail },
            {
              projection: {
                name: 1,
                email: 1,
                image: 1,
                phone: 1,
                bio: 1,
                role: 1,
              },
            }
          );

    const tuitionWithTutor = {
      ...tuition,
      tutor: {
        _id: tutorUser?._id ?? tuition.tutorId,
        name: tutorUser?.name || tuition.tutorName || 'Tutor',
        email: tutorUser?.email || tuition.tutorEmail,
        image: tutorUser?.image,
        phone: tutorUser?.phone,
        bio: tutorUser?.bio,
      },
    };

    res.json({ tuition: tuitionWithTutor });
  } catch (error) {
    next(error);
  }
});

/** Tutor creates a new tuition. New posts remain pending for moderation. */
app.post('/api/tuitions', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user || req.user.role !== 'tutor') {
      res.status(403).json({
        message: 'Only tutors can create tuitions',
      });
      return;
    }

    const parseResult = tuitionSchema.safeParse(req.body);

    if (!parseResult.success) {
      res.status(400).json({
        message: 'Invalid tuition data',
        issues: parseResult.error.issues,
      });
      return;
    }

    const data = parseResult.data;

    const existingCount = await getDb().collection<TuitionDoc>('tuitions').countDocuments({ tutorId: req.user._id });

    if (req.user.plan === 'free' && existingCount >= 2) {
      res.status(403).json({
        message: 'Free tutors may create at most 2 tuitions',
      });
      return;
    }

    const fee = data.monthlyFee ?? data.price ?? 0;

    const tuition: Partial<TuitionDoc> & Record<string, unknown> = {
      tutorId: req.user._id,

      title: data.title,
      description: data.description,

      subject: data.subject,
      classLevel: data.classLevel,
      category: data.category,

      mode: data.mode,
      location: data.location,
      area: data.area,

      monthlyFee: fee,
      price: fee,

      daysPerWeek: data.daysPerWeek,
      preferredDays: data.preferredDays,
      preferredTime: data.preferredTime,

      studentsCount: data.studentsCount,
      studentGender: data.studentGender,
      tutorGender: data.tutorGender,

      requirements: data.requirements,
      contactNumber: data.contactNumber,

      bannerImage: data.bannerImage,

      tutorName: req.user.name ?? '',
      tutorEmail: req.user.email,

      approvalStatus: TuitionApprovalStatus.PENDING,
      status: TuitionStatus.PENDING,

      isActive: data.active ?? true,
      active: data.active ?? true,

      createdAt: new Date(),
    };

    const result = await getDb()
      .collection<TuitionDoc>('tuitions')
      .insertOne(tuition as TuitionDoc);

    const inserted = await getDb().collection<TuitionDoc>('tuitions').findOne({ _id: result.insertedId });

    res.status(201).json({ tuition: inserted });
  } catch (error) {
    next(error);
  }
});

/** Tutor updates own tuition. */
app.patch('/api/tuitions/:id', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user || req.user.role !== 'tutor') {
      res.status(403).json({
        message: 'Only tutors can edit tuitions',
      });
      return;
    }

    const id = req.params.id;

    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid tuition id' });
      return;
    }

    const tuition = await getDb()
      .collection<TuitionDoc>('tuitions')
      .findOne({ _id: new ObjectId(id) });

    if (!tuition) {
      res.status(404).json({ message: 'Tuition not found' });
      return;
    }

    if (!tuition.tutorId.equals(req.user._id)) {
      res.status(403).json({
        message: 'You do not own this tuition',
      });
      return;
    }

    // Remember whether the tuition is currently approved so we can require
    // re-moderation after any listing change (edited listings must not bypass
    // admin moderation).
    const wasApproved =
      tuition.approvalStatus === TuitionApprovalStatus.APPROVED ||
      tuition.status === TuitionStatus.APPROVED;

    // All supported editable tuition fields.
    const partialSchema = z.object({
      title: z.string().min(1).optional(),
      description: z.string().min(1).optional(),

      subject: z.string().optional(),
      classLevel: z.string().optional(),
      category: z.string().optional(),

      mode: z.enum(['online', 'offline', 'hybrid']).optional(),

      location: z.string().optional(),
      area: z.string().optional(),

      monthlyFee: z.number().nonnegative().optional(),
      price: z.number().nonnegative().optional(),

      daysPerWeek: z.number().int().positive().optional(),
      preferredDays: z.array(z.string()).optional(),
      preferredTime: z.string().optional(),

      studentsCount: z.number().int().min(1).optional(),

      studentGender: z.string().optional(),
      tutorGender: z.string().optional(),

      requirements: z.string().optional(),
      contactNumber: z.string().optional(),

      bannerImage: z.string().optional(),

      active: z.boolean().optional(),
    });

    const parseResult = partialSchema.safeParse(req.body);

    if (!parseResult.success) {
      res.status(400).json({
        message: 'Invalid tuition update',
        issues: parseResult.error.issues,
      });
      return;
    }

    const update = parseResult.data as Record<string, unknown>;

    // Keep monthlyFee and price synchronized.
    if (update.price !== undefined && update.monthlyFee === undefined) {
      update.monthlyFee = update.price;
    } else if (update.monthlyFee !== undefined && update.price === undefined) {
      update.price = update.monthlyFee;
    }

    // Keep active and isActive synchronized.
    if (update.active !== undefined) {
      update.isActive = update.active;
    }

    // An edited approved tuition must return to pending for admin review;
    // it must not bypass moderation.
    if (wasApproved) {
      update.approvalStatus = TuitionApprovalStatus.PENDING;
      update.status = TuitionStatus.PENDING;
    }

    await getDb()
      .collection<TuitionDoc>('tuitions')
      .updateOne(
        { _id: new ObjectId(id) },
        {
          $set: update,
          $currentDate: { updatedAt: true },
        }
      );

    const refreshed = await getDb()
      .collection<TuitionDoc>('tuitions')
      .findOne({ _id: new ObjectId(id) });

    res.json({ tuition: refreshed });
  } catch (error) {
    next(error);
  }
});

/** Tutor deletes own tuition. */
app.delete('/api/tuitions/:id', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user || req.user.role !== 'tutor') {
      res.status(403).json({
        message: 'Only tutors can delete tuitions',
      });
      return;
    }

    const id = req.params.id;

    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid tuition id' });
      return;
    }

    const tuition = await getDb()
      .collection<TuitionDoc>('tuitions')
      .findOne({ _id: new ObjectId(id) });

    if (!tuition) {
      res.status(404).json({ message: 'Tuition not found' });
      return;
    }

    if (!tuition.tutorId.equals(req.user._id)) {
      res.status(403).json({
        message: 'You do not own this tuition',
      });
      return;
    }

    const tuitionObjectId = new ObjectId(id);

    // Delete the tuition.
    await getDb().collection<TuitionDoc>('tuitions').deleteOne({ _id: tuitionObjectId });

    // Handle related applications safely: remove applications for this tuition
    // so no orphaned references remain.
    await getDb()
      .collection<ApplicationDoc>('applications')
      .deleteMany({ tuitionId: tuitionObjectId });

    // Remove this tuition from every student's saved bookmarks so deleted
    // listings never resurface in a saved-tuitions list.
    await getDb()
      .collection<UserDoc>('users')
      .updateMany({}, { $pull: { savedTuitionIds: id } });

    res.json({ message: 'Tuition deleted' });
  } catch (error) {
    next(error);
  }
});

const BOOKMARK_FREE_LIMIT = 5;

/** Bookmark schemas. */
const bookmarkIdSchema = z.object({
  id: z.string().refine((val) => ObjectId.isValid(val), { message: 'Invalid tuition id' }),
});

/** Student adds a tuition to their saved bookmarks (Free: max 5, Pro: unlimited). */
app.post(
  '/api/tuitions/:id/bookmark',
  verifyToken,
  async (req: AuthedRequest, res, next) => {
    try {
      // Only students may use student bookmarking (not tutors or admins).
      if (!req.user || req.user.role !== 'student') {
        res.status(403).json({
          message: 'Only students can bookmark tuitions',
        });
        return;
      }

      const parseResult = bookmarkIdSchema.safeParse({ id: req.params.id });
      if (!parseResult.success) {
        res.status(400).json({ message: 'Invalid tuition id' });
        return;
      }

      const tuitionId = parseResult.data.id;

      const tuition = await getDb()
        .collection<TuitionDoc>('tuitions')
        .findOne({ _id: new ObjectId(tuitionId) });

      if (!tuition) {
        res.status(404).json({ message: 'Tuition not found' });
        return;
      }

      const userId = req.user._id;

      const currentUser = await getDb()
        .collection<UserDoc>('users')
        .findOne({ _id: userId });

      const savedIds: string[] = currentUser?.savedTuitionIds ?? [];

      // Prevent duplicate bookmarks.
      if (savedIds.includes(tuitionId)) {
        const refreshed = await getDb()
          .collection<UserDoc>('users')
          .findOne({ _id: userId });
        return res.json({
          message: 'Tuition is already saved',
          saved: false,
          alreadySaved: true,
          savedTuitionIds: refreshed?.savedTuitionIds ?? [],
        });
      }

      // Enforce Free plan limit on the backend.
      if (req.user.plan !== 'pro' && savedIds.length >= BOOKMARK_FREE_LIMIT) {
        return res.status(403).json({
          message:
            'You have reached the free plan limit of 5 saved tuitions. Upgrade to Pro for unlimited bookmarks.',
          limitReached: true,
          limit: BOOKMARK_FREE_LIMIT,
          saved: false,
          savedTuitionIds: savedIds,
        });
      }

      await getDb()
        .collection<UserDoc>('users')
        .updateOne(
          { _id: userId },
          { $push: { savedTuitionIds: tuitionId }, $currentDate: { updatedAt: true } }
        );

      const refreshed = await getDb()
        .collection<UserDoc>('users')
        .findOne({ _id: userId });

      res.status(201).json({
        message: 'Tuition saved successfully',
        saved: true,
        savedTuitionIds: refreshed?.savedTuitionIds ?? [],
      });
    } catch (error) {
      next(error);
    }
  }
);

/** Student removes a tuition from their saved bookmarks. */
app.delete(
  '/api/tuitions/:id/bookmark',
  verifyToken,
  async (req: AuthedRequest, res, next) => {
    try {
      if (!req.user || req.user.role !== 'student') {
        res.status(403).json({
          message: 'Only students can remove bookmarks',
        });
        return;
      }

      const parseResult = bookmarkIdSchema.safeParse({ id: req.params.id });
      if (!parseResult.success) {
        res.status(400).json({ message: 'Invalid tuition id' });
        return;
      }

      const tuitionId = parseResult.data.id;

      const userId = req.user._id;

      await getDb()
        .collection<UserDoc>('users')
        .updateOne(
          { _id: userId },
          { $pull: { savedTuitionIds: tuitionId }, $currentDate: { updatedAt: true } }
        );

      const refreshed = await getDb()
        .collection<UserDoc>('users')
        .findOne({ _id: userId });

      res.json({
        message: 'Bookmark removed',
        saved: false,
        savedTuitionIds: refreshed?.savedTuitionIds ?? [],
      });
    } catch (error) {
      next(error);
    }
  }
);


/** Tutor activates or closes their own tuition (isActive toggle). */
app.patch(
  '/api/tuitions/:id/active',
  verifyToken,
  async (req: AuthedRequest, res, next) => {
    try {
      if (!req.user || req.user.role !== 'tutor') {
        res.status(403).json({ message: 'Only tutors can activate or close tuitions' });
        return;
      }

      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        res.status(400).json({ message: 'Invalid tuition id' });
        return;
      }

      const schema = z.object({
        isActive: z.boolean(),
      });

      const parseResult = schema.safeParse(req.body);

      if (!parseResult.success) {
        res.status(400).json({ message: 'Invalid request', issues: parseResult.error.issues });
        return;
      }

      const { isActive } = parseResult.data;

      const tuition = await getDb()
        .collection<TuitionDoc>('tuitions')
        .findOne({ _id: new ObjectId(id) });

      if (!tuition) {
        res.status(404).json({ message: 'Tuition not found' });
        return;
      }

      if (!tuition.tutorId.equals(req.user._id)) {
        res.status(403).json({ message: 'You do not own this tuition' });
        return;
      }

      // Approval status is preserved independently of active/closed status.
      await getDb()
        .collection<TuitionDoc>('tuitions')
        .updateOne(
          { _id: new ObjectId(id) },
          {
            $set: { isActive, active: isActive },
            $currentDate: { updatedAt: true },
          }
        );

      const refreshed = await getDb()
        .collection<TuitionDoc>('tuitions')
        .findOne({ _id: new ObjectId(id) });

      res.json({
        message: isActive ? 'Tuition activated' : 'Tuition closed',
        tuition: refreshed,
      });
    } catch (error) {
      next(error);
    }
  }
);

/** Admin changes tuition approval status. */
app.patch(
  ['/api/tuitions/:id/status', '/api/admin/tuitions/:id/approval'],
  verifyToken,
  async (req: AuthedRequest, res, next) => {
    try {
      if (req.user?.role !== 'admin') {
        res.status(403).json({ message: 'Admin access required' });
        return;
      }

      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        res.status(400).json({ message: 'Invalid tuition id' });
        return;
      }

      const statusSchema = z
        .object({
          status: z.enum([TuitionStatus.APPROVED, TuitionStatus.REJECTED]).optional(),

          approvalStatus: z.enum([TuitionApprovalStatus.APPROVED, TuitionApprovalStatus.REJECTED]).optional(),
        })
        .refine((data) => data.status !== undefined || data.approvalStatus !== undefined, {
          message: 'Either status or approvalStatus must be provided',
        });

      const parseResult = statusSchema.safeParse(req.body);

      if (!parseResult.success) {
        res.status(400).json({
          message: 'Invalid status',
          issues: parseResult.error.issues,
        });
        return;
      }

      const newStatus = parseResult.data.approvalStatus ?? parseResult.data.status!;

      const result = await getDb()
        .collection<TuitionDoc>('tuitions')
        .updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              approvalStatus: newStatus as TuitionApprovalStatus,
              status: newStatus as TuitionStatus,
            },
            $currentDate: { updatedAt: true },
          }
        );

      if (result.matchedCount === 0) {
        res.status(404).json({ message: 'Tuition not found' });
        return;
      }

      const refreshed = await getDb()
        .collection<TuitionDoc>('tuitions')
        .findOne({ _id: new ObjectId(id) });

      res.json({ tuition: refreshed });
    } catch (error) {
      next(error);
    }
  }
);

// ---------------------------------------------------------------------------
// 9. Application APIs (student & tutor)
// ---------------------------------------------------------------------------

const applicationCreateSchema = z.object({
  tuitionId: z.string().min(1, 'Tuition ID is required'),

  phone: z.string().trim().min(1, 'Phone number is required').max(30),

  education: z.string().trim().min(1, 'Education is required').max(150),

  preferredSchedule: z.string().trim().max(200).optional(),

  preferredDays: z.array(z.string().trim().min(1)).optional(),

  daysPerWeek: z.preprocess(
    (value) => (value === '' || value === null ? undefined : value),
    z.coerce.number().int().min(1).max(7).optional()
  ),

  preferredTime: z.string().trim().max(100).optional(),

  medium: z.string().trim().max(100).optional(),

  academicBackground: z.string().trim().max(1000).optional(),

  studentNote: z.string().trim().max(1000).optional(),

  message: z.string().trim().max(1000).optional(),
});

app.post('/api/applications', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user || req.user.role !== 'student') {
      res.status(403).json({ message: 'Only students can apply' });
      return;
    }

    const parseResult = applicationCreateSchema.safeParse(req.body);

    if (!parseResult.success) {
      res.status(400).json({
        message: 'Invalid application data',
        issues: parseResult.error.issues,
      });
      return;
    }

    const {
      tuitionId,
      phone,
      education,
      preferredSchedule,
      preferredDays,
      daysPerWeek,
      preferredTime,
      medium,
      academicBackground,
      studentNote,
      message,
    } = parseResult.data;

    if (!ObjectId.isValid(tuitionId)) {
      res.status(400).json({ message: 'Invalid tuition id' });
      return;
    }

    const db = getDb();

    const tuition = await db.collection<TuitionDoc>('tuitions').findOne({ _id: new ObjectId(tuitionId) });

    if (!tuition) {
      res.status(404).json({
        message: 'Tuition not found or not open for applications',
      });
      return;
    }

    const isApproved =
      tuition.approvalStatus === TuitionApprovalStatus.APPROVED || tuition.status === TuitionStatus.APPROVED;

    const isActive = tuition.isActive === true || tuition.active === true;

    if (!isApproved || !isActive) {
      res.status(404).json({
        message: 'Tuition not found or not open for applications',
      });
      return;
    }

    const isOwnTuition =
      (tuition.tutorId && new ObjectId(tuition.tutorId).equals(req.user._id)) || tuition.tutorEmail === req.user.email;

    if (isOwnTuition) {
      res.status(400).json({
        message: 'Tutors cannot apply to their own tuition',
      });
      return;
    }

    const existing = await db.collection<ApplicationDoc>('applications').findOne({
      tuitionId: new ObjectId(tuitionId),
      $or: [{ studentId: req.user._id }, { studentEmail: req.user.email }],
    });

    if (existing) {
      res.status(409).json({
        message: 'Application already exists for this tuition',
      });
      return;
    }

    const finalSchedule = preferredSchedule?.trim() || undefined;

    const finalNote = studentNote?.trim() || message?.trim() || undefined;

    const now = new Date();

    const appDoc: Partial<ApplicationDoc> & Record<string, unknown> = {
      tuitionId: new ObjectId(tuitionId),

      tuitionTitle: tuition.title,
      subject: tuition.subject,
      classLevel: tuition.classLevel,
      monthlyFee: tuition.monthlyFee ?? tuition.price ?? 0,

      tutorId: tuition.tutorId,
      tutorEmail: tuition.tutorEmail,

      studentId: req.user._id,
      studentName: req.user.name ?? '',
      studentEmail: req.user.email,

      // Student submitted information
      studentPhone: phone.trim(),
      education: education.trim(),

      preferredSchedule: finalSchedule,
      preferredDays: preferredDays ?? [],
      daysPerWeek: daysPerWeek,
      preferredTime: preferredTime?.trim() || undefined,

      medium: medium?.trim() || undefined,
      academicBackground: academicBackground?.trim() || undefined,

      studentNote: finalNote,
      message: message?.trim() || finalNote,

      status: ApplicationStatus.PENDING,

      appliedAt: now,
      createdAt: now,
      updatedAt: now,
    };

    const result = await db.collection<ApplicationDoc>('applications').insertOne(appDoc as ApplicationDoc);

    const inserted = await db.collection<ApplicationDoc>('applications').findOne({ _id: result.insertedId });

    res.status(201).json({
      message: 'Application submitted successfully',
      application: inserted,
    });
  } catch (error: unknown) {
    if ((error as { code?: number })?.code === 11000) {
      res.status(409).json({
        message: 'Application already exists for this tuition',
      });
      return;
    }

    next(error);
  }
});

app.get(
  ['/api/applications/my', '/api/applications/my-applications'],
  verifyToken,
  async (req: AuthedRequest, res, next) => {
    try {
      if (!req.user || req.user.role !== 'student') {
        res.status(403).json({
          message: 'Only students have a My Applications view',
        });
        return;
      }

      const db = getDb();

      const apps = await db
        .collection<ApplicationDoc>('applications')
        .find({
          $or: [{ studentId: req.user._id }, { studentEmail: req.user.email }],
        })
        .sort({ appliedAt: -1, createdAt: -1 })
        .toArray();

      const tuitionIds = [...new Set(apps.map((a) => a.tuitionId).filter(Boolean))];

      const tuitions = await db
        .collection<TuitionDoc>('tuitions')
        .find({ _id: { $in: tuitionIds } })
        .toArray();

      const tuitionMap = new Map(tuitions.map((t) => [t._id.toString(), t]));

      const enrichedApps = apps.map((application) => {
        const tuition = tuitionMap.get(application.tuitionId.toString());

        return {
          ...application,

          student: {
            _id: application.studentId,
            name: application.studentName,
            email: application.studentEmail,
            phone: application.studentPhone,
            education: application.education,
          },

          createdAt: application.appliedAt || application.createdAt || new Date(),

          tuition: {
            _id: application.tuitionId,
            title: application.tuitionTitle || tuition?.title || '',
            subject: application.subject || tuition?.subject || '',
            classLevel: tuition?.classLevel || '',
            className: tuition?.classLevel || '',
            location: tuition?.location || '',
            monthlyFee: application.monthlyFee || tuition?.monthlyFee || tuition?.price || 0,
            salary: application.monthlyFee || tuition?.monthlyFee || tuition?.price || 0,
            tutorName: tuition?.tutorName || '',
            tutorEmail: tuition?.tutorEmail || application.tutorEmail,
          },
        };
      });

      res.json({ applications: enrichedApps });
    } catch (error) {
      next(error);
    }
  }
);

app.get('/api/applications/tutor', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user || (req.user.role !== 'tutor' && req.user.role !== 'admin')) {
      res.status(403).json({
        message: 'Only tutors can view applications to their tuitions',
      });
      return;
    }

    const db = getDb();
    const isTutor = req.user.role === 'tutor';

    const tutorTuitions = isTutor
      ? await db
          .collection<TuitionDoc>('tuitions')
          .find({
            $or: [{ tutorId: req.user._id }, { tutorEmail: req.user.email }],
          })
          .toArray()
      : await db.collection<TuitionDoc>('tuitions').find({}).toArray();

    const tuitionMap = new Map(tutorTuitions.map((t) => [t._id.toString(), t]));

    const tuitionIds = tutorTuitions.map((t) => t._id);

    const apps = isTutor
      ? await db
          .collection<ApplicationDoc>('applications')
          .find({
            $or: [{ tuitionId: { $in: tuitionIds } }, { tutorId: req.user._id }, { tutorEmail: req.user.email }],
          })
          .sort({ appliedAt: -1, createdAt: -1 })
          .toArray()
      : await db
          .collection<ApplicationDoc>('applications')
          .find({})
          .sort({ appliedAt: -1, createdAt: -1 })
          .toArray();

    const studentEmails = [...new Set(apps.map((a) => a.studentEmail).filter(Boolean))];

    const studentIds = [...new Set(apps.map((a) => a.studentId).filter(Boolean))];

    const students = await db
      .collection<UserDoc>('users')
      .find({
        $or: [{ email: { $in: studentEmails } }, { _id: { $in: studentIds } }],
      })
      .toArray();

    const studentMap = new Map(students.map((s) => [s.email, s]));

    const studentIdMap = new Map(students.map((s) => [s._id.toString(), s]));

    const enrichedApps = apps.map((application) => {
      const tuition = tuitionMap.get(application.tuitionId.toString());

      const student =
        (application.studentId && studentIdMap.get(application.studentId.toString())) ||
        studentMap.get(application.studentEmail);

      return {
        ...application,

        // Applicant's submitted information
        student: {
          _id: student?._id ? student._id.toString() : application.studentId?.toString() || '',

          name: application.studentName || student?.name || 'Unknown Student',

          email: application.studentEmail,

          // Use the phone number submitted with this application.
          phone: application.studentPhone || student?.phone || '',

          education: application.education || '',

          avatar: student?.image,
        },

        // All application-specific details
        applicantDetails: {
          phone: application.studentPhone || '',
          education: application.education || '',
          preferredSchedule: application.preferredSchedule || '',
          preferredDays: application.preferredDays || [],
          daysPerWeek: application.daysPerWeek ?? null,
          preferredTime: application.preferredTime || '',
          medium: application.medium || '',
          academicBackground: application.academicBackground || '',
          studentNote: application.studentNote || '',
          message: application.message || '',
        },

        tuition: {
          _id: application.tuitionId,
          title: application.tuitionTitle || tuition?.title || 'Tuition',

          subject: application.subject || tuition?.subject || 'Subject',

          classLevel: tuition?.classLevel || '',

          location: tuition?.location || 'Location not specified',

          monthlyFee: application.monthlyFee || tuition?.monthlyFee || tuition?.price || 0,

          salary: application.monthlyFee || tuition?.monthlyFee || tuition?.price || 0,
        },

        createdAt: application.appliedAt || application.createdAt || new Date(),
      };
    });

    res.json({ applications: enrichedApps });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/applications/:id/status', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user || req.user.role !== 'tutor') {
      res.status(403).json({
        message: 'Only tutors can change application status',
      });
      return;
    }

    const appId = req.params.id;

    if (!ObjectId.isValid(appId)) {
      res.status(400).json({ message: 'Invalid application id' });
      return;
    }

    const statusSchema = z.object({
      status: z.enum([ApplicationStatus.ACCEPTED, ApplicationStatus.REJECTED, 'approved']),
    });

    const parseResult = statusSchema.safeParse(req.body);

    if (!parseResult.success) {
      res.status(400).json({
        message: 'Invalid status',
        issues: parseResult.error.issues,
      });
      return;
    }

    const application = await getDb()
      .collection<ApplicationDoc>('applications')
      .findOne({ _id: new ObjectId(appId) });

    if (!application) {
      res.status(404).json({ message: 'Application not found' });
      return;
    }

    const tuition = await getDb().collection<TuitionDoc>('tuitions').findOne({ _id: application.tuitionId });

    const isOwner =
      (tuition?.tutorId && new ObjectId(tuition.tutorId).equals(req.user._id)) ||
      tuition?.tutorEmail === req.user.email ||
      (application.tutorId && new ObjectId(application.tutorId).equals(req.user._id)) ||
      application.tutorEmail === req.user.email;

    if (!isOwner) {
      res.status(403).json({
        message: 'You do not own this application',
      });
      return;
    }

    const targetStatus = parseResult.data.status === 'approved' ? ApplicationStatus.ACCEPTED : parseResult.data.status;

    await getDb()
      .collection<ApplicationDoc>('applications')
      .updateOne(
        { _id: new ObjectId(appId) },
        {
          $set: { status: targetStatus },
          $currentDate: { updatedAt: true },
        }
      );

    const refreshed = await getDb()
      .collection<ApplicationDoc>('applications')
      .findOne({ _id: new ObjectId(appId) });

    res.json({ application: refreshed });
  } catch (error) {
    next(error);
  }
});

app.delete('/api/applications/:id', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user || req.user.role !== 'student') {
      res.status(403).json({
        message: 'Only students can delete applications',
      });
      return;
    }

    const appId = req.params.id;

    if (!ObjectId.isValid(appId)) {
      res.status(400).json({ message: 'Invalid application id' });
      return;
    }

    const application = await getDb()
      .collection<ApplicationDoc>('applications')
      .findOne({ _id: new ObjectId(appId) });

    if (!application) {
      res.status(404).json({ message: 'Application not found' });
      return;
    }

    const isOwner =
      (application.studentId && new ObjectId(application.studentId).equals(req.user._id)) ||
      application.studentEmail === req.user.email;

    if (!isOwner) {
      res.status(403).json({
        message: 'You do not own this application',
      });
      return;
    }

    if (application.status !== ApplicationStatus.PENDING) {
      res.status(400).json({
        message: 'Only pending applications can be canceled',
      });
      return;
    }

    await getDb()
      .collection<ApplicationDoc>('applications')
      .deleteOne({ _id: new ObjectId(appId) });

    res.json({ message: 'Application canceled' });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// 10. Dashboard APIs (role-based)
// ---------------------------------------------------------------------------

/** Student dashboard. */
app.get('/api/dashboard/student', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user || req.user.role !== 'student') {
      res.status(403).json({ message: 'Student access required' });
      return;
    }

    const studentEmail = req.user.email;
    const studentId = req.user._id;

    const applicationsColl = getDb().collection<ApplicationDoc>('applications');
    const tuitionColl = getDb().collection<TuitionDoc>('tuitions');

    const studentFilter = {
      $or: [{ studentEmail }, { studentId }],
    };

    const [total, pending, accepted, rejected] = await Promise.all([
      applicationsColl.countDocuments(studentFilter),
      applicationsColl.countDocuments({
        ...studentFilter,
        status: ApplicationStatus.PENDING,
      }),
      applicationsColl.countDocuments({
        ...studentFilter,
        status: { $in: [ApplicationStatus.ACCEPTED, 'approved'] },
      }),
      applicationsColl.countDocuments({
        ...studentFilter,
        status: ApplicationStatus.REJECTED,
      }),
    ]);

    const recentApplications = await applicationsColl
      .find(studentFilter)
      .sort({ appliedAt: -1, createdAt: -1 })
      .limit(5)
      .toArray();

    const tuitionIds = recentApplications.map((appDoc) => appDoc.tuitionId);

    const recentTuitions = await tuitionColl
      .find({ _id: { $in: tuitionIds } }, { projection: { title: 1, subject: 1, tutorName: 1 } })
      .toArray();

    res.json({
      stats: { total, pending, accepted, rejected },
      recentApplications,
      recentTuitions,
    });
  } catch (error) {
    next(error);
  }
});

/** Tutor dashboard. */
app.get('/api/dashboard/tutor', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user || req.user.role !== 'tutor') {
      res.status(403).json({ message: 'Tutor access required' });
      return;
    }

    const tutorId = req.user._id;

    const tuitionColl = getDb().collection<TuitionDoc>('tuitions');
    const applicationColl = getDb().collection<ApplicationDoc>('applications');

    const [totalTuitions, pendingTuitions, approvedTuitions, rejectedTuitions, activeTuitions] = await Promise.all([
      tuitionColl.countDocuments({ tutorId }),
      tuitionColl.countDocuments({
        tutorId,
        $or: [{ approvalStatus: TuitionApprovalStatus.PENDING }, { status: TuitionStatus.PENDING }],
      }),
      tuitionColl.countDocuments({
        tutorId,
        $or: [{ approvalStatus: TuitionApprovalStatus.APPROVED }, { status: TuitionStatus.APPROVED }],
      }),
      tuitionColl.countDocuments({
        tutorId,
        $or: [{ approvalStatus: TuitionApprovalStatus.REJECTED }, { status: TuitionStatus.REJECTED }],
      }),
      tuitionColl.countDocuments({
        tutorId,
        $or: [
          {
            isActive: true,
            approvalStatus: TuitionApprovalStatus.APPROVED,
          },
          {
            active: true,
            status: TuitionStatus.APPROVED,
          },
        ],
      }),
    ]);

    const tutorTuitions = await tuitionColl
      .find({ tutorId }, { projection: { _id: 1, title: 1, subject: 1 } })
      .toArray();

    const tuitionIds = tutorTuitions.map((t) => t._id);

    const [totalApplicants, pendingApplicants, acceptedApplicants] = await Promise.all([
      applicationColl.countDocuments({
        tuitionId: { $in: tuitionIds },
      }),
      applicationColl.countDocuments({
        tuitionId: { $in: tuitionIds },
        status: ApplicationStatus.PENDING,
      }),
      applicationColl.countDocuments({
        tuitionId: { $in: tuitionIds },
        status: { $in: [ApplicationStatus.ACCEPTED, 'approved'] },
      }),
    ]);

    const recentTuitions = await tuitionColl.find({ tutorId }).sort({ createdAt: -1 }).limit(5).toArray();

    const rawRecentApplications = await applicationColl
      .find({ tuitionId: { $in: tuitionIds } })
      .sort({ appliedAt: -1, createdAt: -1 })
      .limit(5)
      .toArray();

    const tuitionMap = new Map(tutorTuitions.map((t) => [t._id.toString(), t]));

    const recentApplications = rawRecentApplications.map((appDoc) => {
      const tuition = tuitionMap.get(appDoc.tuitionId.toString());

      return {
        ...appDoc,
        tuition: {
          _id: appDoc.tuitionId,
          title: appDoc.tuitionTitle || tuition?.title || 'Tuition',
          subject: appDoc.subject || tuition?.subject || 'Subject',
        },
      };
    });

    res.json({
      stats: {
        totalTuitions,
        pendingTuitions,
        approvedTuitions,
        rejectedTuitions,
        activeTuitions,
        totalApplicants,
        pendingApplicants,
        acceptedApplicants,
      },
      recentTuitions,
      recentApplications,
    });
  } catch (error) {
    next(error);
  }
});

/** Admin dashboard. */
app.get('/api/dashboard/admin', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (req.user?.role !== 'admin') {
      res.status(403).json({ message: 'Admin access required' });
      return;
    }

    const db = getDb();

    const usersColl = db.collection<UserDoc>('users');
    const tuitionsColl = db.collection<TuitionDoc>('tuitions');
    const applicationsColl = db.collection<ApplicationDoc>('applications');
    const paymentsColl = db.collection<Payment>('payments');
    const subscriptionsColl = db.collection<Subscription>('subscriptions');

    const [totalUsers, studentCount, tutorCount, adminCount] = await Promise.all([
      usersColl.countDocuments({}),
      usersColl.countDocuments({ role: 'student' }),
      usersColl.countDocuments({ role: 'tutor' }),
      usersColl.countDocuments({ role: 'admin' }),
    ]);

    const [freeMemberCount, premiumMemberCount] = await Promise.all([
      usersColl.countDocuments({ plan: 'free' }),
      usersColl.countDocuments({ plan: 'pro' }),
    ]);

    const [totalTuitions, pendingTuitions, approvedTuitions, rejectedTuitions] = await Promise.all([
      tuitionsColl.countDocuments({}),
      tuitionsColl.countDocuments({
        $or: [{ approvalStatus: TuitionApprovalStatus.PENDING }, { status: TuitionStatus.PENDING }],
      }),
      tuitionsColl.countDocuments({
        $or: [{ approvalStatus: TuitionApprovalStatus.APPROVED }, { status: TuitionStatus.APPROVED }],
      }),
      tuitionsColl.countDocuments({
        $or: [{ approvalStatus: TuitionApprovalStatus.REJECTED }, { status: TuitionStatus.REJECTED }],
      }),
    ]);

    const totalApplications = await applicationsColl.countDocuments({});

    const [activeSubscriptions, canceledSubscriptions] = await Promise.all([
      subscriptionsColl.countDocuments({ status: { $in: ['active', 'trialing'] } }),
      subscriptionsColl.countDocuments({ status: 'canceled' }),
    ]);

    const paymentAgg = await paymentsColl
      .aggregate<{ totalRevenue: number; count: number }>(
        [
          { $match: { paymentStatus: 'paid' } },
          {
            $group: {
              _id: null,
              totalRevenue: { $sum: '$amount' },
              count: { $sum: 1 },
            },
          },
        ]
      )
      .toArray();

    const pendingPaymentCount = await paymentsColl.countDocuments({ $or: [{ paymentStatus: 'pending' }, { status: 'pending' }] });
    const failedPaymentCount = await paymentsColl.countDocuments({ $or: [{ paymentStatus: 'failed' }, { status: 'failed' }] });

    const paymentStats = paymentAgg[0] || {
      totalRevenue: 0,
      count: 0,
    };

    const recentUsers = await usersColl.find({}).sort({ createdAt: -1 }).limit(5).toArray();

    const recentTuitions = await tuitionsColl.find({}).sort({ createdAt: -1 }).limit(5).toArray();

    const recentPayments = await paymentsColl
      .find({ paymentStatus: 'paid' })
      .sort({ paidAt: -1 })
      .limit(5)
      .toArray();

    res.json({
      users: {
        total: totalUsers,
        studentCount,
        tutorCount,
        adminCount,
        freeMembers: freeMemberCount,
        premiumMembers: premiumMemberCount,
        recent: recentUsers,
      },
      tuitions: {
        total: totalTuitions,
        pending: pendingTuitions,
        approved: approvedTuitions,
        rejected: rejectedTuitions,
        recent: recentTuitions,
      },
      applications: {
        total: totalApplications,
      },
      subscriptions: {
        active: activeSubscriptions,
        canceled: canceledSubscriptions,
      },
      payments: {
        totalPaid: paymentStats.count,
        totalRevenue: paymentStats.totalRevenue,
        pending: pendingPaymentCount,
        failed: failedPaymentCount,
        recent: recentPayments,
      },
      stats: {
        totalUsers,
        studentCount,
        tutorCount,
        adminCount,
        freeMembers: freeMemberCount,
        premiumMembers: premiumMemberCount,
        totalTuitions,
        pendingTuitions,
        approvedTuitions,
        rejectedTuitions,
        totalApplications,
        activeSubscriptions,
        canceledSubscriptions,
        totalRevenue: paymentStats.totalRevenue,
        paidCount: paymentStats.count,
        pendingPayments: pendingPaymentCount,
        failedPayments: failedPaymentCount,
      },
      recentUsers,
      recentTuitions,
      recentPayments,
    });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// 11. Payment & Stripe APIs
// ---------------------------------------------------------------------------

/**
 * Upserts a subscription record from a Stripe Subscription object and links it
 * to a MongoDB user. Idempotent on stripeSubscriptionId.
 */
async function upsertSubscriptionRecord(
  db: Db,
  sub: Stripe.Subscription,
  { userId, userEmail, userRole }: { userId: ObjectId; userEmail: string; userRole: Role },
): Promise<void> {
  const customerId = typeof sub.customer === 'string' ? sub.customer : sub.customer?.id || '';
  const priceId = sub.items?.data?.[0]?.price?.id || '';
  const status = sub.status as Subscription['status'];
  const currentPeriodStart = new Date((sub as any).current_period_start * 1000);
  const currentPeriodEnd = new Date((sub as any).current_period_end * 1000);
  const isProActive = status === 'active' || status === 'trialing';

  await db.collection<Subscription>('subscriptions').updateOne(
    { stripeSubscriptionId: sub.id },
    {
      $set: {
        userId,
        userEmail,
        userRole,
        plan: isProActive ? 'pro' : 'free',
        stripeCustomerId: customerId,
        stripeSubscriptionId: sub.id,
        stripePriceId: priceId,
        status,
        currentPeriodStart,
        currentPeriodEnd,
        cancelAtPeriodEnd: sub.cancel_at_period_end,
        updatedAt: new Date(),
      },
      $setOnInsert: {
        _id: new ObjectId(),
        createdAt: new Date(),
      },
    },
    { upsert: true }
  );
}

/**
 * Creates a Stripe Checkout Session for subscription upgrade.
 * Validates authentication, role, active subscription status, and sets metadata.
 */
app.post('/api/payments/create-checkout-session', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user) {
      res.status(401).json({ message: 'Authentication required. Please sign in.' });
      return;
    }

    if (req.user.role === 'admin') {
      res.status(400).json({ message: 'Admin accounts already have full platform access.' });
      return;
    }

    if (!stripe) {
      res.status(503).json({ message: 'Stripe payments are not configured on the server.' });
      return;
    }

    const db = getDb();

    // Prevent duplicate active subscriptions
    const activeSub = await db.collection<Subscription>('subscriptions').findOne({
      userId: req.user._id,
      status: { $in: ['active', 'trialing'] },
    });

    if (activeSub || req.user.plan === 'pro') {
      res.status(400).json({ message: 'You already have an active Pro subscription.' });
      return;
    }

    // Resolve or create Stripe customer
    let stripeCustomerId = req.user.stripeCustomerId;
    if (!stripeCustomerId) {
      const prevPayment = await db.collection<Payment>('payments').findOne({
        userId: req.user._id,
        stripeCustomerId: { $exists: true, $ne: '' },
      });
      if (prevPayment?.stripeCustomerId) {
        stripeCustomerId = prevPayment.stripeCustomerId;
      }
    }

    if (!stripeCustomerId) {
      const customer = await stripe.customers.create({
        email: req.user.email,
        name: req.user.name,
        metadata: {
          userId: req.user._id.toString(),
          role: req.user.role,
        },
      });
      stripeCustomerId = customer.id;
      await db.collection<UserDoc>('users').updateOne(
        { _id: req.user._id },
        { $set: { stripeCustomerId, updatedAt: new Date() } }
      );
    }

    const isTutor = req.user.role === 'tutor';
    const planTitle = isTutor ? 'Tutor Pro' : 'Student Pro';
    const planName = isTutor ? 'tutor-pro' : 'student-pro';
    const unitAmount = isTutor ? 1500 : 1000; // $15 for tutor, $10 for student (in cents)

    const configuredPriceId =
      (isTutor ? env.stripePriceIdTutor : env.stripePriceIdStudent) || env.stripePriceId;

    const lineItems: Stripe.Checkout.SessionCreateParams.LineItem[] = configuredPriceId
      ? [{ price: configuredPriceId, quantity: 1 }]
      : [
          {
            price_data: {
              currency: 'usd',
              product_data: {
                name: planTitle,
                description: `${planTitle} monthly subscription on MentorLagbe`,
              },
              unit_amount: unitAmount,
              recurring: {
                interval: 'month',
              },
            },
            quantity: 1,
          },
        ];

    const session = await stripe.checkout.sessions.create({
      customer: stripeCustomerId,
      mode: 'subscription',
      line_items: lineItems,
      success_url: `${env.clientUrl}/payment/success?payment=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${env.clientUrl}/payment/success?payment=cancelled`,
      metadata: {
        userId: req.user._id.toString(),
        userEmail: req.user.email,
        userName: req.user.name || 'Subscriber',
        userRole: req.user.role,
        planName,
        plan: 'pro',
      },
      subscription_data: {
        metadata: {
          userId: req.user._id.toString(),
          userEmail: req.user.email,
          userName: req.user.name || 'Subscriber',
          userRole: req.user.role,
          planName,
          plan: 'pro',
        },
      },
    });

    // Record pending payment in MongoDB
    await db.collection<Payment>('payments').insertOne({
      _id: new ObjectId(),
      userId: req.user._id,
      userEmail: req.user.email,
      userName: req.user.name || 'Subscriber',
      userRole: req.user.role,
      planName,
      amount: isTutor ? 15 : 10,
      currency: 'usd',
      status: 'pending',
      paymentStatus: 'pending',
      paymentType: 'subscription',
      stripeCustomerId,
      stripeCheckoutSessionId: session.id,
      stripeSessionId: session.id,
      transactionId: session.id,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    res.json({
      url: session.url,
      sessionId: session.id,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Stripe Webhook handler.
 * Verifies webhook signatures using the raw body, enforces idempotency,
 * and handles subscription lifecycle events safely.
 */
app.post('/api/payments/webhook', async (req, res) => {
  if (!stripe) {
    res.status(503).json({ message: 'Stripe is not configured' });
    return;
  }

  const sig = req.headers['stripe-signature'];
  if (!sig || !env.stripeWebhookSecret) {
    res.status(400).send('Missing stripe signature or webhook secret configuration');
    return;
  }

  const rawBody = (req as any).rawBody || req.body;
  let event: Stripe.Event;

  try {
    event = stripe.webhooks.constructEvent(rawBody, sig as string, env.stripeWebhookSecret);
  } catch (err: any) {
    console.error('[stripe webhook] Signature verification failed:', err?.message);
    res.status(400).send(`Webhook Error: ${err?.message}`);
    return;
  }

  const db = getDb();
  const eventsColl = db.collection<ProcessedEvent>('processed_events');

  // Idempotency: skip events we already fully processed.
  const already = await eventsColl.findOne({ eventId: event.id });
  if (already) {
    console.log(`[stripe webhook] Event ${event.id} already processed. Acknowledging.`);
    res.json({ received: true, duplicate: true });
    return;
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object as Stripe.Checkout.Session;
        const userIdStr = session.metadata?.userId;
        const customerId = typeof session.customer === 'string' ? session.customer : session.customer?.id || '';
        const subId = typeof session.subscription === 'string' ? session.subscription : session.subscription?.id || '';
        const paymentIntentId =
          typeof session.payment_intent === 'string' ? session.payment_intent : session.payment_intent?.id || '';
        const userRole = (session.metadata?.userRole || 'student') as Role;
        const planName = (session.metadata?.planName || (userRole === 'tutor' ? 'tutor-pro' : 'student-pro')) as Payment['planName'];
        const amountTotal = session.amount_total ? session.amount_total / 100 : (userRole === 'tutor' ? 15 : 10);
        // For subscription mode, payment_status can be 'paid', 'no_payment_required', or 'unpaid'
        // Treat 'no_payment_required' as paid (e.g., free trials, $0 subscriptions)
        const isPaid = session.payment_status === 'paid' || session.payment_status === 'no_payment_required';

        const userObjectId = userIdStr && ObjectId.isValid(userIdStr) ? new ObjectId(userIdStr) : null;

        const setFields: Record<string, unknown> = {
          status: isPaid ? 'paid' : 'pending',
          paymentStatus: isPaid ? 'paid' : 'pending',
          amount: amountTotal,
          currency: session.currency || 'usd',
          stripeCustomerId: customerId,
          stripeSubscriptionId: subId,
          stripePaymentIntentId: paymentIntentId,
          paymentMethod: (session as any).payment_method_types?.[0] || null,
          updatedAt: new Date(),
        };
        if (isPaid) {
          setFields.paidAt = new Date();
        }

        // Build the update operation - only insert if we have a valid user identifier
        const updateOperation: Record<string, unknown> = { $set: setFields };
        if (userObjectId) {
          updateOperation.$setOnInsert = {
            _id: new ObjectId(),
            userId: userObjectId,
            userEmail: session.metadata?.userEmail || '',
            userName: session.metadata?.userName || 'Subscriber',
            userRole,
            planName,
            paymentType: 'subscription',
            transactionId: session.id,
            createdAt: new Date(),
          };
        } else if (session.metadata?.userEmail) {
          // Fallback: try to find user by email for $setOnInsert
          const userByEmail = await db.collection<UserDoc>('users').findOne({ email: session.metadata.userEmail });
          if (userByEmail) {
            updateOperation.$setOnInsert = {
              _id: new ObjectId(),
              userId: userByEmail._id,
              userEmail: session.metadata.userEmail,
              userName: session.metadata?.userName || userByEmail.name || 'Subscriber',
              userRole: userByEmail.role,
              planName,
              paymentType: 'subscription',
              transactionId: session.id,
              createdAt: new Date(),
            };
          }
        }

        await db.collection<Payment>('payments').updateOne(
          { stripeCheckoutSessionId: session.id },
          updateOperation,
          { upsert: true }
        );

        // Only a verified, paid checkout may activate Premium membership.
        // Determine the target user ID for plan upgrade
        let targetUserId: ObjectId | null = userObjectId;
        if (!targetUserId && session.metadata?.userEmail) {
          const userByEmail = await db.collection<UserDoc>('users').findOne({ email: session.metadata.userEmail });
          if (userByEmail) targetUserId = userByEmail._id;
        }

        if (isPaid && targetUserId) {
          await db.collection<UserDoc>('users').updateOne(
            { _id: targetUserId },
            { $set: { plan: 'pro', stripeCustomerId: customerId || '', updatedAt: new Date() } }
          );

          if (subId) {
            try {
              const sub = await stripe.subscriptions.retrieve(subId);
              await upsertSubscriptionRecord(db, sub, {
                userId: targetUserId,
                userEmail: session.metadata?.userEmail || '',
                userRole,
              });
            } catch {
              await db.collection<Subscription>('subscriptions').updateOne(
                { stripeSubscriptionId: subId },
                {
                  $set: {
                    userId: targetUserId,
                    userEmail: session.metadata?.userEmail || '',
                    userRole,
                    plan: 'pro',
                    stripeCustomerId: customerId || '',
                    stripeSubscriptionId: subId,
                    status: 'active',
                    updatedAt: new Date(),
                  },
                  $setOnInsert: {
                    _id: new ObjectId(),
                    createdAt: new Date(),
                  },
                },
                { upsert: true }
              );
            }
          }
        }
        break;
      }

      case 'invoice.paid': {
        const invoice = event.data.object as Stripe.Invoice;
        const customerId = typeof invoice.customer === 'string' ? invoice.customer : invoice.customer?.id || '';
        const subId = typeof (invoice as any).subscription === 'string' ? (invoice as any).subscription : (invoice as any).subscription?.id || '';
        const paymentIntentId =
          typeof (invoice as any).payment_intent === 'string' ? (invoice as any).payment_intent : (invoice as any).payment_intent?.id || '';
        const amount = invoice.amount_paid ? invoice.amount_paid / 100 : 0;
        const currency = invoice.currency || 'usd';

        let user: UserDoc | null = null;
        if (customerId) {
          user = await db.collection<UserDoc>('users').findOne({ stripeCustomerId: customerId });
        }

        // Update the existing payment linked to this invoice. Never insert a
        // brand-new payment here, to avoid duplicating the checkout-session record.
        const paymentFilter: Record<string, unknown> = {};
        if (paymentIntentId) paymentFilter.stripePaymentIntentId = paymentIntentId;
        if (subId) paymentFilter.stripeSubscriptionId = subId;
        if (!paymentIntentId && !subId && customerId) {
          paymentFilter.stripeCustomerId = customerId;
        }

        if (Object.keys(paymentFilter).length > 0) {
          await db.collection<Payment>('payments').updateOne(
            paymentFilter,
            {
              $set: {
                status: 'paid',
                paymentStatus: 'paid',
                amount,
                currency,
                stripeCustomerId: customerId,
                stripeSubscriptionId: subId,
                stripePaymentIntentId: paymentIntentId,
                paidAt: new Date(),
                updatedAt: new Date(),
              },
            }
          );
        }

        if (user) {
          await db.collection<UserDoc>('users').updateOne(
            { _id: user._id },
            { $set: { plan: 'pro', stripeCustomerId: customerId || user.stripeCustomerId || '', updatedAt: new Date() } }
          );
        }

        if (subId && user) {
          try {
            const sub = await stripe.subscriptions.retrieve(subId);
            await upsertSubscriptionRecord(db, sub, {
              userId: user._id,
              userEmail: user.email,
              userRole: user.role,
            });
          } catch {
            await db.collection<Subscription>('subscriptions').updateOne(
              { stripeSubscriptionId: subId },
              {
                $set: {
                  userId: user._id,
                  userEmail: user.email,
                  userRole: user.role,
                  plan: 'pro',
                  stripeCustomerId: customerId || '',
                  status: 'active',
                  updatedAt: new Date(),
                },
                $setOnInsert: {
                  _id: new ObjectId(),
                  createdAt: new Date(),
                },
              },
              { upsert: true }
            );
          }
        }
        break;
      }

      case 'customer.subscription.created':
      case 'customer.subscription.updated': {
        const sub = event.data.object as Stripe.Subscription;
        const customerId = typeof sub.customer === 'string' ? sub.customer : sub.customer?.id || '';
        const userIdStr = sub.metadata?.userId;

        let user: UserDoc | null = null;
        if (userIdStr && ObjectId.isValid(userIdStr)) {
          user = await db.collection<UserDoc>('users').findOne({ _id: new ObjectId(userIdStr) });
        }
        if (!user && customerId) {
          user = await db.collection<UserDoc>('users').findOne({ stripeCustomerId: customerId });
        }

        if (user) {
          await upsertSubscriptionRecord(db, sub, {
            userId: user._id,
            userEmail: user.email,
            userRole: user.role,
          });

          const status = sub.status;
          const isProActive = status === 'active' || status === 'trialing';

          await db.collection<UserDoc>('users').updateOne(
            { _id: user._id },
            {
              $set: {
                plan: isProActive ? 'pro' : 'free',
                stripeCustomerId: customerId || user.stripeCustomerId || '',
                updatedAt: new Date(),
              },
            }
          );
        }
        break;
      }

      case 'customer.subscription.deleted': {
        const sub = event.data.object as Stripe.Subscription;
        const customerId = typeof sub.customer === 'string' ? sub.customer : sub.customer?.id || '';

        await db.collection<Subscription>('subscriptions').updateOne(
          { stripeSubscriptionId: sub.id },
          {
            $set: { status: 'canceled', plan: 'free', updatedAt: new Date() },
          }
        );

        const user = customerId ? await db.collection<UserDoc>('users').findOne({ stripeCustomerId: customerId }) : null;
        if (user) {
          await db.collection<UserDoc>('users').updateOne(
            { _id: user._id },
            { $set: { plan: 'free', updatedAt: new Date() } }
          );
        }
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object as Stripe.Invoice;
        const customerId = typeof invoice.customer === 'string' ? invoice.customer : invoice.customer?.id || '';
        const subId = typeof (invoice as any).subscription === 'string' ? (invoice as any).subscription : (invoice as any).subscription?.id || '';
        const paymentIntentId =
          typeof (invoice as any).payment_intent === 'string' ? (invoice as any).payment_intent : (invoice as any).payment_intent?.id || '';

        const filter: Record<string, unknown> = {};
        if (paymentIntentId) filter.stripePaymentIntentId = paymentIntentId;
        if (subId) filter.stripeSubscriptionId = subId;
        if (!paymentIntentId && !subId && customerId) filter.stripeCustomerId = customerId;

        if (Object.keys(filter).length > 0) {
          await db.collection<Payment>('payments').updateOne(
            filter,
            { $set: { status: 'failed', paymentStatus: 'failed', updatedAt: new Date() } }
          );
        }

        if (subId) {
          await db.collection<Subscription>('subscriptions').updateOne(
            { stripeSubscriptionId: subId },
            { $set: { status: 'past_due', updatedAt: new Date() } }
          );
        }
        break;
      }

      default:
        console.log(`[stripe webhook] Unhandled event type: ${event.type}`);
    }

    // Record the event only after successful handling.
    try {
      await eventsColl.insertOne({
        _id: new ObjectId(),
        eventId: event.id,
        type: event.type,
        processedAt: new Date(),
      });
    } catch (err: any) {
      if (err?.code !== 11000) {
        console.error('[stripe webhook] Idempotency record error:', err);
      }
    }

    res.json({ received: true });
  } catch (handlerError) {
    console.error('[stripe webhook] Error processing event:', handlerError);
    res.status(500).json({ error: 'Webhook processing error' });
  }
});

/**
 * Returns the current authenticated user's active subscription information.
 */
app.get('/api/payments/my-subscription', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user) {
      res.status(401).json({ message: 'Authentication required. Please sign in.' });
      return;
    }

    const db = getDb();
    const sub = await db.collection<Subscription>('subscriptions').findOne(
      { userId: req.user._id },
      { sort: { createdAt: -1 } }
    );

    const isPro = req.user.plan === 'pro' || sub?.status === 'active' || sub?.status === 'trialing';

    res.json({
      plan: isPro ? 'pro' : 'free',
      isPro,
      subscription: sub
        ? {
            id: sub._id.toString(),
            status: sub.status,
            plan: sub.plan,
            stripePriceId: sub.stripePriceId,
            currentPeriodStart: sub.currentPeriodStart,
            currentPeriodEnd: sub.currentPeriodEnd,
            cancelAtPeriodEnd: sub.cancelAtPeriodEnd,
            createdAt: sub.createdAt,
          }
        : null,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Returns payment history for the authenticated user.
 */
app.get('/api/payments/history', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user) {
      res.status(401).json({ message: 'Authentication required. Please sign in.' });
      return;
    }

    const db = getDb();
    const payments = await db
      .collection<Payment>('payments')
      .find({
        $or: [{ userId: req.user._id }, { userEmail: req.user.email }],
      })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({ payments });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// 11b. Admin Payment Management
// ---------------------------------------------------------------------------

/**
 * Returns a paginated, filterable list of payments for admins.
 * Only administrators may list all users' payments.
 */
app.get('/api/admin/payments', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (req.user?.role !== 'admin') {
      res.status(403).json({ message: 'Admin access required' });
      return;
    }

    const {
      page = '1',
      limit = '20',
      search,
      status,
      plan,
      startDate,
      endDate,
      sortBy = 'createdAt',
      sortOrder = 'desc',
    } = req.query as Record<string, string | undefined>;

    const filter: Record<string, unknown> = {};
    const andConditions: Record<string, unknown>[] = [];

    if (status) {
      andConditions.push({ $or: [{ paymentStatus: status }, { status }] });
    }

    if (plan) {
      filter.planName = plan;
    }

    if (startDate || endDate) {
      const dateFilter: Record<string, unknown> = {};
      if (startDate) dateFilter.$gte = new Date(startDate);
      if (endDate) dateFilter.$lte = new Date(endDate);
      andConditions.push({ $or: [{ createdAt: dateFilter }, { paidAt: dateFilter }] });
    }

    if (search) {
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(escaped, 'i');
      andConditions.push({
        $or: [
          { userName: { $regex: regex } },
          { userEmail: { $regex: regex } },
          { transactionId: { $regex: regex } },
          { stripeCheckoutSessionId: { $regex: regex } },
          { stripeSubscriptionId: { $regex: regex } },
        ],
      });
    }

    if (andConditions.length > 0) {
      filter.$and = andConditions;
    }

    const pageNum = Math.max(parseInt(page || '1', 10) || 1, 1);
    const limitNum = Math.min(Math.max(parseInt(limit || '20', 10) || 20, 1), 100);
    const skip = (pageNum - 1) * limitNum;

    const validSortFields = ['createdAt', 'paidAt', 'amount', 'userName', 'userEmail', 'status', 'paymentStatus'];
    const sortField = validSortFields.includes(sortBy || '') ? sortBy! : 'createdAt';
    const sort: Record<string, 1 | -1> = {};
    sort[sortField] = sortOrder === 'asc' ? 1 : -1;

    const db = getDb();
    const paymentsColl = db.collection<Payment>('payments');

    const [payments, total, paidSummary, pendingCount, failedCount] = await Promise.all([
      paymentsColl.find(filter).sort(sort).skip(skip).limit(limitNum).toArray(),
      paymentsColl.countDocuments(filter),
      paymentsColl
        .aggregate<{ totalAmount: number; count: number }>([
          {
            $match: {
              $and: [filter, { $or: [{ status: 'paid' }, { paymentStatus: 'paid' }] }],
            },
          },
          {
            $group: {
              _id: null,
              totalAmount: { $sum: '$amount' },
              count: { $sum: 1 },
            },
          },
        ])
        .toArray(),
      paymentsColl.countDocuments({
        ...filter,
        $or: [{ status: 'pending' }, { paymentStatus: 'pending' }],
      }),
      paymentsColl.countDocuments({
        ...filter,
        $or: [{ status: 'failed' }, { paymentStatus: 'failed' }],
      }),
    ]);

    const totalPages = Math.ceil(total / limitNum) || 1;

    res.json({
      payments,
      total,
      page: pageNum,
      limit: limitNum,
      totalPages,
      summary: {
        totalPaidAmount: paidSummary[0]?.totalAmount ?? 0,
        paidCount: paidSummary[0]?.count ?? 0,
        pendingCount,
        failedCount,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Returns a single payment's details for admins.
 */
app.get('/api/admin/payments/:id', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (req.user?.role !== 'admin') {
      res.status(403).json({ message: 'Admin access required' });
      return;
    }

    const id = req.params.id;

    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid payment id' });
      return;
    }

    const db = getDb();
    const payment = await db.collection<Payment>('payments').findOne({ _id: new ObjectId(id) });

    if (!payment) {
      res.status(404).json({ message: 'Payment not found' });
      return;
    }

    const sub = await db.collection<Subscription>('subscriptions').findOne({
      $or: [{ stripeSubscriptionId: payment.stripeSubscriptionId }, { userId: payment.userId }],
    });

    res.json({ payment, subscription: sub ?? null });
  } catch (error) {
    next(error);
  }
});

/**
 * Admin manually approves a pending payment after verifying with Stripe.
 * Only for payments that are stuck in pending state due to webhook issues.
 * Verifies directly with Stripe before approving.
 */
app.patch('/api/admin/payments/:id/approve', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (req.user?.role !== 'admin') {
      res.status(403).json({ message: 'Admin access required' });
      return;
    }

    if (!stripe) {
      res.status(503).json({ message: 'Stripe payments are not configured.' });
      return;
    }

    const id = req.params.id;

    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid payment id' });
      return;
    }

    const db = getDb();
    const payment = await db.collection<Payment>('payments').findOne({ _id: new ObjectId(id) });

    if (!payment) {
      res.status(404).json({ message: 'Payment not found' });
      return;
    }

    // Only allow approval for pending payments
    const currentStatus = payment.paymentStatus ?? payment.status;
    if (currentStatus === 'paid') {
      res.status(400).json({ message: 'Payment is already approved/paid' });
      return;
    }

    if (currentStatus === 'failed' || currentStatus === 'canceled' || currentStatus === 'refunded') {
      res.status(400).json({ message: `Cannot approve a ${currentStatus} payment` });
      return;
    }

    // Verify with Stripe using the checkout session ID
    const sessionId = payment.stripeCheckoutSessionId || payment.stripeSessionId;
    if (!sessionId) {
      res.status(400).json({ message: 'No Stripe session ID found for this payment' });
      return;
    }

    let session: Stripe.Checkout.Session;
    try {
      session = await stripe.checkout.sessions.retrieve(sessionId);
    } catch (stripeErr) {
      console.error('[admin approve] Stripe session retrieval failed:', stripeErr);
      res.status(400).json({ message: 'Failed to verify payment with Stripe' });
      return;
    }

    // Check payment status from Stripe
    const isPaid = session.payment_status === 'paid' || session.payment_status === 'no_payment_required';
    if (!isPaid) {
      res.status(400).json({
        message: `Stripe reports payment status: ${session.payment_status}. Cannot approve unpaid payment.`,
      });
      return;
    }

    // Verify the session belongs to the payment's user
    if (session.metadata?.userId && payment.userId) {
      const sessionUserId = session.metadata.userId;
      const paymentUserId = payment.userId.toString();
      if (sessionUserId !== paymentUserId) {
        res.status(400).json({ message: 'Stripe session user does not match payment record' });
        return;
      }
    }

    // Update payment record
    const customerId = typeof session.customer === 'string' ? session.customer : session.customer?.id || '';
    const subId = typeof session.subscription === 'string' ? session.subscription : session.subscription?.id || '';
    const paymentIntentId =
      typeof session.payment_intent === 'string' ? session.payment_intent : session.payment_intent?.id || '';
    const amountTotal = session.amount_total ? session.amount_total / 100 : payment.amount;

    await db.collection<Payment>('payments').updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          status: 'paid',
          paymentStatus: 'paid',
          amount: amountTotal,
          currency: session.currency || payment.currency || 'usd',
          stripeCustomerId: customerId,
          stripeSubscriptionId: subId,
          stripePaymentIntentId: paymentIntentId,
          paymentMethod: (session as any).payment_method_types?.[0] || payment.paymentMethod || null,
          paidAt: new Date(),
          updatedAt: new Date(),
        },
      }
    );

    // Upgrade user to Pro plan
    if (payment.userId) {
      await db.collection<UserDoc>('users').updateOne(
        { _id: payment.userId },
        { $set: { plan: 'pro', stripeCustomerId: customerId || payment.stripeCustomerId || '', updatedAt: new Date() } }
      );
    }

    // Sync subscription if available
    if (subId && payment.userId) {
      try {
        const sub = await stripe.subscriptions.retrieve(subId);
        await upsertSubscriptionRecord(db, sub, {
          userId: payment.userId,
          userEmail: payment.userEmail || session.metadata?.userEmail || '',
          userRole: payment.userRole || (session.metadata?.userRole as Role) || 'student',
        });
      } catch (subErr) {
        console.warn('[admin approve] Could not sync Stripe subscription:', subErr);
        await db.collection<Subscription>('subscriptions').updateOne(
          { stripeSubscriptionId: subId },
          {
            $set: {
              userId: payment.userId,
              userEmail: payment.userEmail || session.metadata?.userEmail || '',
              userRole: payment.userRole || (session.metadata?.userRole as Role) || 'student',
              plan: 'pro',
              stripeCustomerId: customerId || '',
              stripeSubscriptionId: subId,
              status: 'active',
              updatedAt: new Date(),
            },
            $setOnInsert: {
              _id: new ObjectId(),
              createdAt: new Date(),
            },
          },
          { upsert: true }
        );
      }
    }

    const updatedPayment = await db.collection<Payment>('payments').findOne({ _id: new ObjectId(id) });
    res.json({ payment: updatedPayment, message: 'Payment approved and user upgraded to Pro' });
  } catch (error) {
    next(error);
  }
});

/**
 * Securely verifies a checkout session with Stripe and syncs state if paid.
 */
app.get('/api/payments/verify-session/:sessionId', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user) {
      res.status(401).json({ message: 'Authentication required. Please sign in.' });
      return;
    }

    if (!stripe) {
      res.status(503).json({ message: 'Stripe payments are not configured.' });
      return;
    }

    const session = await stripe.checkout.sessions.retrieve(req.params.sessionId);

    const sessionCustomerId =
      typeof session.customer === 'string' ? session.customer : session.customer?.id || '';

    // A checkout session may only ever be verified by the user who created it.
    // Sessions minted by this server always carry metadata.userId; the customer
    // id is a second check for sessions created before that metadata existed.
    if (session.metadata?.userId) {
      if (session.metadata.userId !== req.user._id.toString()) {
        res.status(403).json({ message: 'Unauthorized session verification.' });
        return;
      }
    } else if (!sessionCustomerId || sessionCustomerId !== req.user.stripeCustomerId) {
      res.status(403).json({ message: 'Unauthorized session verification.' });
      return;
    }

    const db = getDb();

    const linkedPayment = await db
      .collection<Payment>('payments')
      .findOne({ stripeCheckoutSessionId: session.id });

    if (linkedPayment?.userId && linkedPayment.userId.toString() !== req.user._id.toString()) {
      res.status(403).json({ message: 'Unauthorized session verification.' });
      return;
    }

    // For subscription mode, payment_status can be 'paid', 'no_payment_required', or 'unpaid'
    const isPaid = session.payment_status === 'paid' || session.payment_status === 'no_payment_required';

    if (isPaid) {
      const amount = session.amount_total ? session.amount_total / 100 : linkedPayment?.amount;
      const paymentIntentId =
        typeof session.payment_intent === 'string' ? session.payment_intent : session.payment_intent?.id || '';

      await db.collection<Payment>('payments').updateOne(
        { stripeCheckoutSessionId: session.id },
        {
          $set: {
            status: 'paid',
            paymentStatus: 'paid',
            ...(typeof amount === 'number' ? { amount } : {}),
            currency: session.currency || linkedPayment?.currency || 'usd',
            stripeCustomerId: sessionCustomerId || linkedPayment?.stripeCustomerId || '',
            stripePaymentIntentId: paymentIntentId || linkedPayment?.stripePaymentIntentId || '',
            paymentMethod:
              (session as any).payment_method_types?.[0] || linkedPayment?.paymentMethod || null,
            paidAt: new Date(),
            updatedAt: new Date(),
          },
        }
      );

      await db.collection<UserDoc>('users').updateOne(
        { _id: req.user._id },
        { $set: { plan: 'pro', updatedAt: new Date() } }
      );

      const subId = typeof session.subscription === 'string' ? session.subscription : session.subscription?.id;
      if (subId) {
        try {
          const sub = await stripe.subscriptions.retrieve(subId);
          await db.collection<Subscription>('subscriptions').updateOne(
            { stripeSubscriptionId: sub.id },
            {
              $set: {
                userId: req.user._id,
                userEmail: req.user.email,
                userRole: req.user.role,
                plan: 'pro',
                stripeCustomerId: typeof sub.customer === 'string' ? sub.customer : sub.customer.id,
                stripeSubscriptionId: sub.id,
                stripePriceId: sub.items.data[0]?.price?.id || '',
                status: sub.status as any,
                currentPeriodStart: new Date((sub as any).current_period_start * 1000),
                currentPeriodEnd: new Date((sub as any).current_period_end * 1000),
                cancelAtPeriodEnd: sub.cancel_at_period_end,
                updatedAt: new Date(),
              },
              $setOnInsert: {
                _id: new ObjectId(),
                createdAt: new Date(),
              },
            },
            { upsert: true }
          );
        } catch (subErr) {
          console.warn('[verify-session] Could not sync Stripe subscription:', subErr);
        }
      }
    }

    res.json({
      success: isPaid,
      paymentStatus: session.payment_status,
      plan: isPaid ? 'pro' : req.user.plan || 'free',
    });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// 12. Public platform statistics & secure image upload
// ---------------------------------------------------------------------------

/**
 * Public, read-only platform counters used by the homepage.
 * Only aggregate counts are exposed — no personal data.
 */
app.get('/api/stats', async (_req, res, next) => {
  try {
    const db = getDb();

    const approvedAndActive = {
      $or: [{ approvalStatus: TuitionApprovalStatus.APPROVED }, { status: TuitionStatus.APPROVED }],
      $and: [{ $or: [{ isActive: true }, { active: true }] }],
    } as Record<string, unknown>;

    const [tuitions, tutors, students, applications, acceptedApplications] = await Promise.all([
      db.collection<TuitionDoc>('tuitions').countDocuments(approvedAndActive),
      db.collection<UserDoc>('users').countDocuments({ role: 'tutor' }),
      db.collection<UserDoc>('users').countDocuments({ role: 'student' }),
      db.collection<ApplicationDoc>('applications').countDocuments({}),
      db
        .collection<ApplicationDoc>('applications')
        .countDocuments({ status: { $in: [ApplicationStatus.ACCEPTED, 'approved'] } }),
    ]);

    res.set('Cache-Control', 'public, max-age=60');
    res.json({
      stats: {
        tuitions,
        tutors,
        students,
        applications,
        acceptedApplications,
      },
    });
  } catch (error) {
    next(error);
  }
});

interface ImgBBResponse {
  data?: {
    url?: string;
    display_url?: string;
    delete_url?: string;
    width?: number;
    height?: number;
  };
  error?: { message?: string };
}

/**
 * Secure ImgBB image upload.
 *
 * The ImgBB API key stays on the server; the client only sends a base64
 * image (validated for type and size). The returned permanent URL is what
 * callers must persist (for example as a tuition `bannerImage`).
 */
app.post('/api/upload/image', verifyToken, async (req: AuthedRequest, res, next) => {
  try {
    if (!req.user) {
      res.status(401).json({ message: 'Authentication required. Please sign in.' });
      return;
    }

    if (!env.imgbbApiKey) {
      res.status(503).json({ message: 'Image uploads are not configured on the server.' });
      return;
    }

    const schema = z.object({
      image: z.string().min(1, 'Image data is required'),
      name: z.string().max(120).optional(),
    });

    const parseResult = schema.safeParse(req.body);

    if (!parseResult.success) {
      res.status(400).json({
        message: 'Invalid image payload',
        issues: parseResult.error.issues,
      });
      return;
    }

    const raw = parseResult.data.image.trim();
    const dataUrlMatch = raw.match(/^data:(image\/(?:png|jpeg|jpg|webp|gif));base64,([A-Za-z0-9+/=\s]+)$/);

    let base64 = raw;

    if (raw.startsWith('data:')) {
      if (!dataUrlMatch) {
        res.status(400).json({ message: 'Unsupported image format. Use PNG, JPG, WEBP or GIF.' });
        return;
      }
      base64 = dataUrlMatch[2];
    } else if (!/^[A-Za-z0-9+/=\s]+$/.test(base64)) {
      res.status(400).json({ message: 'Invalid image data.' });
      return;
    }

    const byteLength = Buffer.byteLength(base64, 'base64');

    if (byteLength === 0) {
      res.status(400).json({ message: 'The selected image is empty.' });
      return;
    }

    if (byteLength > 5 * 1024 * 1024) {
      res.status(413).json({ message: 'Image size must be less than 5MB.' });
      return;
    }

    const form = new URLSearchParams();
    form.set('key', env.imgbbApiKey);
    form.set('image', base64);
    if (parseResult.data.name) {
      form.set('name', parseResult.data.name);
    }

    const imgbbResponse = await fetch('https://api.imgbb.com/1/upload', {
      method: 'POST',
      body: form,
    });

    const payload = (await imgbbResponse.json().catch(() => null)) as ImgBBResponse | null;

    if (!imgbbResponse.ok || !payload?.data?.url) {
      console.error('[imgbb] Upload failed:', payload?.error?.message || imgbbResponse.status);
      res.status(502).json({ message: 'Image upload failed. Please try again.' });
      return;
    }

    res.json({
      url: payload.data.url,
      displayUrl: payload.data.display_url || payload.data.url,
      deleteUrl: payload.data.delete_url,
      width: payload.data.width,
      height: payload.data.height,
    });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// 13. 404 & Error handling
// ---------------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).json({
    message: `Route not found: ${req.method} ${req.originalUrl}`,
  });
});

const errorHandler: ErrorRequestHandler = (err, _req, res, next) => {
  console.error('[server error]', err);

  if (res.headersSent) {
    return next(err);
  }

  const statusCode =
    typeof err?.statusCode === 'number' && err.statusCode >= 400 && err.statusCode < 600 ? err.statusCode : 500;

  res.status(statusCode).json({
    message: IS_PRODUCTION ? 'Internal server error' : err?.message || 'Internal server error',
  });
};

app.use(errorHandler);

// ---------------------------------------------------------------------------
// 13. Server startup & shutdown handling
// ---------------------------------------------------------------------------
let server: ReturnType<typeof app.listen> | null = null;

async function startServer(): Promise<void> {
  await connectToDatabase();

  const db = getDb();

  try {
    await Promise.all([
      db.collection<ApplicationDoc>('applications').createIndex({ tuitionId: 1, studentId: 1 }, { background: true }),
      db.collection<TuitionDoc>('tuitions').createIndex({ tutorId: 1 }, { background: true }),
      db.collection<TuitionDoc>('tuitions').createIndex({ approvalStatus: 1, isActive: 1 }, { background: true }),
      db.collection<Payment>('payments').createIndex({ userId: 1 }, { background: true }),
      db.collection<Payment>('payments').createIndex({ stripeCheckoutSessionId: 1 }, { background: true }),
      db.collection<Payment>('payments').createIndex({ stripePaymentIntentId: 1 }, { background: true }),
      db.collection<Subscription>('subscriptions').createIndex({ userId: 1 }, { background: true }),
      db.collection<Subscription>('subscriptions').createIndex({ stripeSubscriptionId: 1 }, { background: true, unique: true, sparse: true }),
      db.collection<Subscription>('subscriptions').createIndex({ stripeCustomerId: 1 }, { background: true }),
      db.collection<ProcessedEvent>('processed_events').createIndex({ eventId: 1 }, { background: true, unique: true }),
    ]);
  } catch (indexError) {
    console.warn('[server] Warning initializing indexes:', indexError);
  }

  authNodeHandler = toNodeHandler(getAuth());

  server = app.listen(env.port, () => {
    console.log(`[server] MentorLagbe API listening on http://localhost:${env.port}`);
  });
}

function handleShutdown(signal: string) {
  console.log(`[server] Received ${signal}. Shutting down gracefully...`);

  if (server) {
    server.close(() => {
      console.log('[server] HTTP server closed.');
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
}

process.on('SIGINT', () => handleShutdown('SIGINT'));
process.on('SIGTERM', () => handleShutdown('SIGTERM'));

process.on('unhandledRejection', (reason) => {
  console.error('[server] Unhandled Promise Rejection:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('[server] Uncaught Exception:', error);
  process.exit(1);
});

if (!process.env.VERCEL) {
  startServer().catch((error) => {
    console.error('[server] Failed to start:', error);
    process.exit(1);
  });
}

export default app;
