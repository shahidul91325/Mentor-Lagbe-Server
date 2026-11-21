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
 *   4. BetterAuth integration (token minting & route forwarding)
 *   5. Profile APIs (GET /api/users/me, PATCH /api/users/me)
 *   6. Admin Tuition Management
 *   7. Admin User Management
 *   8. Tuition APIs (public, tutor & admin)
 *   9. Application APIs (student & tutor)
 *  10. Dashboard APIs (student, tutor & admin)
 *  11. 404 & Error handling
 *  12. Server startup & shutdown handling
 * ==========================================================================*/
// ---------------------------------------------------------------------------
// 1. Imports and configuration
// ---------------------------------------------------------------------------
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { fromNodeHeaders, toNodeHandler } from 'better-auth/node';
import { env } from './src/env.js';
import { connectToDatabase, getDb } from './src/db.js';
import { getAuth } from './src/better-auth.js';
import { verifyToken } from './src/middleware/auth.js';
import { z } from 'zod';
import { ApplicationStatus, TuitionStatus, TuitionApprovalStatus, } from './src/types.js';
import { ObjectId } from 'mongodb';
const IS_PRODUCTION = env.nodeEnv === 'production';
// ---------------------------------------------------------------------------
// 2. App and middleware setup
// ---------------------------------------------------------------------------
const app = express();
// CORS: allow frontend origin with credentials enabled.
app.use(cors({
    origin: env.clientUrl,
    credentials: true,
}));
// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// ---------------------------------------------------------------------------
// 3. Health check
// ---------------------------------------------------------------------------
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
    }
    catch (error) {
        next(error);
    }
});
// ---------------------------------------------------------------------------
// 4. BetterAuth integration
// ---------------------------------------------------------------------------
/** Mints a MentorLagbe JWT for the current BetterAuth session. */
app.post('/api/auth/token', async (req, res, next) => {
    try {
        const session = await getAuth().api.getSession({ headers: fromNodeHeaders(req.headers) });
        if (!session) {
            res.status(401).json({ message: 'No active session. Please sign in first.' });
            return;
        }
        const token = jwt.sign({ sub: session.user.id }, env.jwtSecret, { expiresIn: '7d' });
        res.json({ token });
    }
    catch (error) {
        next(error);
    }
});
/** Forward all BetterAuth routes (sign‑up, sign‑in, session, etc.). */
let authNodeHandler = null;
app.use('/api/auth', (req, res) => {
    if (!authNodeHandler) {
        res.status(503).json({ message: 'Authentication service is not ready yet' });
        return;
    }
    return authNodeHandler(req, res);
});
// ---------------------------------------------------------------------------
// 5. Profile APIs
// ---------------------------------------------------------------------------
/** Returns the signed‑in user's profile (trusted server‑side data). */
app.get('/api/users/me', verifyToken, (req, res) => {
    if (!req.user) {
        res.status(401).json({ message: 'Authentication required. Please sign in.' });
        return;
    }
    res.json({ user: req.user });
});
/** Update the signed‑in user's profile. */
app.patch('/api/users/me', verifyToken, async (req, res, next) => {
    try {
        if (!req.user) {
            res.status(401).json({ message: 'Authentication required. Please sign in.' });
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
            res.status(400).json({ message: 'Invalid profile data', issues: parseResult.error.issues });
            return;
        }
        const update = parseResult.data;
        const rawBody = req.body;
        if (rawBody.role !== undefined || rawBody.plan !== undefined) {
            res.status(400).json({ message: 'Cannot change role or plan via profile update' });
            return;
        }
        const result = await getDb()
            .collection('users')
            .updateOne({ _id: req.user._id }, { $set: update, $currentDate: { updatedAt: true } });
        if (result.matchedCount === 0) {
            res.status(404).json({ message: 'User not found' });
            return;
        }
        const refreshed = await getDb().collection('users').findOne({ _id: req.user._id });
        res.json({ user: refreshed });
    }
    catch (error) {
        next(error);
    }
});
// ---------------------------------------------------------------------------
// 6. Admin Tuition Management
// ---------------------------------------------------------------------------
/** Admin list all tuitions with optional filtering, pagination, search, and sorting */
app.get('/api/admin/tuitions', verifyToken, async (req, res, next) => {
    try {
        if (req.user?.role !== 'admin') {
            res.status(403).json({ message: 'Admin access required' });
            return;
        }
        const { status, search, page = '1', limit = '20', sortBy = 'createdAt', sortOrder = 'desc', } = req.query;
        const filter = {};
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
        const sortField = validSortFields.includes(sortBy || '') ? sortBy : 'createdAt';
        const sort = {};
        sort[sortField] = sortOrder === 'asc' ? 1 : -1;
        const cursor = getDb().collection('tuitions').find(filter).sort(sort).skip(skip).limit(limitNum);
        const tuitions = await cursor.toArray();
        const total = await getDb().collection('tuitions').countDocuments(filter);
        const totalPages = Math.ceil(total / limitNum) || 1;
        res.json({ tuitions, total, page: pageNum, limit: limitNum, totalPages });
    }
    catch (error) {
        next(error);
    }
});
/** Admin approve a pending tuition */
app.patch('/api/admin/tuitions/:id/approve', verifyToken, async (req, res, next) => {
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
            .collection('tuitions')
            .findOne({ _id: new ObjectId(id) });
        if (!tuition) {
            res.status(404).json({ message: 'Tuition not found' });
            return;
        }
        if (tuition.approvalStatus !== TuitionApprovalStatus.PENDING && tuition.status !== TuitionStatus.PENDING) {
            res.status(400).json({ message: 'Only pending tuitions can be approved' });
            return;
        }
        await getDb()
            .collection('tuitions')
            .updateOne({ _id: new ObjectId(id) }, {
            $set: {
                approvalStatus: TuitionApprovalStatus.APPROVED,
                status: TuitionStatus.APPROVED,
            },
            $currentDate: { updatedAt: true },
        });
        const refreshed = await getDb()
            .collection('tuitions')
            .findOne({ _id: new ObjectId(id) });
        res.json({ tuition: refreshed });
    }
    catch (error) {
        next(error);
    }
});
/** Admin reject a pending tuition */
app.patch('/api/admin/tuitions/:id/reject', verifyToken, async (req, res, next) => {
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
            .collection('tuitions')
            .findOne({ _id: new ObjectId(id) });
        if (!tuition) {
            res.status(404).json({ message: 'Tuition not found' });
            return;
        }
        if (tuition.approvalStatus !== TuitionApprovalStatus.PENDING && tuition.status !== TuitionStatus.PENDING) {
            res.status(400).json({ message: 'Only pending tuitions can be rejected' });
            return;
        }
        await getDb()
            .collection('tuitions')
            .updateOne({ _id: new ObjectId(id) }, {
            $set: {
                approvalStatus: TuitionApprovalStatus.REJECTED,
                status: TuitionStatus.REJECTED,
            },
            $currentDate: { updatedAt: true },
        });
        const refreshed = await getDb()
            .collection('tuitions')
            .findOne({ _id: new ObjectId(id) });
        res.json({ tuition: refreshed });
    }
    catch (error) {
        next(error);
    }
});
/** Admin view full tuition details */
app.get('/api/admin/tuitions/:id', verifyToken, async (req, res, next) => {
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
            .collection('tuitions')
            .findOne({ _id: new ObjectId(id) });
        if (!tuition) {
            res.status(404).json({ message: 'Tuition not found' });
            return;
        }
        res.json({ tuition });
    }
    catch (error) {
        next(error);
    }
});
// ---------------------------------------------------------------------------
// 7. Admin User Management
// ---------------------------------------------------------------------------
/** List users with pagination, search, and role filter */
app.get('/api/admin/users', verifyToken, async (req, res, next) => {
    try {
        if (req.user?.role !== 'admin') {
            res.status(403).json({ message: 'Admin access required' });
            return;
        }
        const { role, search, page = '1', limit = '20', sortBy = 'createdAt', sortOrder = 'desc', } = req.query;
        const filter = {};
        if (role)
            filter.role = role;
        if (search) {
            const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const regex = new RegExp(escaped, 'i');
            filter.$or = [{ email: { $regex: regex } }, { name: { $regex: regex } }];
        }
        const pageNum = Math.max(parseInt(page || '1', 10) || 1, 1);
        const limitNum = Math.min(Math.max(parseInt(limit || '20', 10) || 20, 1), 100);
        const skip = (pageNum - 1) * limitNum;
        const validSortFields = ['createdAt', 'email', 'name', 'role'];
        const sortField = validSortFields.includes(sortBy || '') ? sortBy : 'createdAt';
        const sort = {};
        sort[sortField] = sortOrder === 'asc' ? 1 : -1;
        const cursor = getDb().collection('users').find(filter).sort(sort).skip(skip).limit(limitNum);
        const users = await cursor.toArray();
        const total = await getDb().collection('users').countDocuments(filter);
        const totalPages = Math.ceil(total / limitNum) || 1;
        res.json({ users, total, page: pageNum, limit: limitNum, totalPages });
    }
    catch (error) {
        next(error);
    }
});
/** View a single user */
app.get('/api/admin/users/:id', verifyToken, async (req, res, next) => {
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
            .collection('users')
            .findOne({ _id: new ObjectId(id) });
        if (!user) {
            res.status(404).json({ message: 'User not found' });
            return;
        }
        res.json({ user });
    }
    catch (error) {
        next(error);
    }
});
/** Change a user's role */
app.patch('/api/admin/users/:id/role', verifyToken, async (req, res, next) => {
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
        const schema = z.object({ role: z.enum(['student', 'tutor', 'admin']) });
        const parseResult = schema.safeParse(req.body);
        if (!parseResult.success) {
            res.status(400).json({ message: 'Invalid role payload', issues: parseResult.error.issues });
            return;
        }
        const newRole = parseResult.data.role;
        if (req.user._id.equals(new ObjectId(id)) && newRole !== 'admin') {
            res.status(400).json({ message: 'Admins cannot demote themselves' });
            return;
        }
        if (newRole !== 'admin') {
            const adminCount = await getDb().collection('users').countDocuments({ role: 'admin' });
            const targetUser = await getDb()
                .collection('users')
                .findOne({ _id: new ObjectId(id) });
            if (targetUser?.role === 'admin' && adminCount <= 1) {
                res.status(400).json({ message: 'Cannot remove the last admin' });
                return;
            }
        }
        await getDb()
            .collection('users')
            .updateOne({ _id: new ObjectId(id) }, { $set: { role: newRole }, $currentDate: { updatedAt: true } });
        const updated = await getDb()
            .collection('users')
            .findOne({ _id: new ObjectId(id) });
        res.json({ user: updated });
    }
    catch (error) {
        next(error);
    }
});
// ---------------------------------------------------------------------------
// 8. Tuition APIs (public, tutor & admin)
// ---------------------------------------------------------------------------
/** Schema for creating/updating a tuition. */
const tuitionSchema = z
    .object({
    title: z.string().min(1, 'Title is required'),
    description: z.string().min(1, 'Description is required'),
    subject: z.string().optional().default('General'),
    classLevel: z.string().optional().default('All Levels'),
    mode: z.enum(['online', 'offline', 'hybrid']).optional().default('online'),
    location: z.string().optional(),
    monthlyFee: z.number().nonnegative().optional(),
    price: z.number().nonnegative().optional(),
    daysPerWeek: z.number().int().positive().optional().default(3),
    bannerImage: z.string().optional(),
    active: z.boolean().optional(),
})
    .refine((data) => data.monthlyFee !== undefined || data.price !== undefined, {
    message: 'Either monthlyFee or price must be provided',
});
/** Get public list of approved and active tuitions. */
app.get('/api/tuitions', async (req, res, next) => {
    try {
        const querySchema = z
            .object({
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
            res.status(400).json({ message: 'Invalid query parameters', issues: parseResult.error.issues });
            return;
        }
        const { search, subject, classLevel, mode, location, minFee, maxFee, page, limit, sortBy, sortOrder } = parseResult.data;
        const filter = {
            $or: [
                { approvalStatus: TuitionApprovalStatus.APPROVED },
                { status: TuitionStatus.APPROVED },
            ],
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
        if (subject)
            filter.subject = subject;
        if (classLevel)
            filter.classLevel = classLevel;
        if (mode)
            filter.mode = mode;
        if (location)
            filter.location = location;
        if (minFee !== undefined || maxFee !== undefined) {
            const feeFilter = {};
            if (minFee !== undefined)
                feeFilter.$gte = minFee;
            if (maxFee !== undefined)
                feeFilter.$lte = maxFee;
            filter.$or = [{ monthlyFee: feeFilter }, { price: feeFilter }];
        }
        const collection = getDb().collection('tuitions');
        const total = await collection.countDocuments(filter);
        const skip = (page - 1) * limit;
        const sortField = sortBy === 'price' ? 'monthlyFee' : sortBy;
        const sort = {};
        sort[sortField] = sortOrder === 'asc' ? 1 : -1;
        const tuitions = await collection.find(filter).sort(sort).skip(skip).limit(limit).toArray();
        const totalPages = Math.ceil(total / limit) || 1;
        res.json({ tuitions, total, page, limit, totalPages });
    }
    catch (error) {
        next(error);
    }
});
/** Tutor view own tuitions (including pending/rejected) */
app.get('/api/tuitions/my', verifyToken, async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'tutor') {
            res.status(403).json({ message: 'Tutor access required' });
            return;
        }
        const tuitions = await getDb().collection('tuitions').find({ tutorId: req.user._id }).toArray();
        res.json({ tuitions });
    }
    catch (error) {
        next(error);
    }
});
/** Get a single tuition if approved and active. */
app.get('/api/tuitions/:id', async (req, res, next) => {
    try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
            res.status(400).json({ message: 'Invalid tuition id' });
            return;
        }
        const tuition = await getDb()
            .collection('tuitions')
            .findOne({
            _id: new ObjectId(id),
            $or: [
                { approvalStatus: TuitionApprovalStatus.APPROVED },
                { status: TuitionStatus.APPROVED },
            ],
            $and: [
                {
                    $or: [{ isActive: true }, { active: true }],
                },
            ],
        });
        if (!tuition) {
            res.status(404).json({ message: 'Tuition not found' });
            return;
        }
        res.json({ tuition });
    }
    catch (error) {
        next(error);
    }
});
/** Tutor creates a new tuition (defaults to pending, active). */
app.post('/api/tuitions', verifyToken, async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'tutor') {
            res.status(403).json({ message: 'Only tutors can create tuitions' });
            return;
        }
        const parseResult = tuitionSchema.safeParse(req.body);
        if (!parseResult.success) {
            res.status(400).json({ message: 'Invalid tuition data', issues: parseResult.error.issues });
            return;
        }
        const data = parseResult.data;
        const existingCount = await getDb().collection('tuitions').countDocuments({ tutorId: req.user._id });
        if (req.user.plan === 'free' && existingCount >= 2) {
            res.status(403).json({ message: 'Free tutors may create at most 2 tuitions' });
            return;
        }
        const fee = data.monthlyFee ?? data.price ?? 0;
        const tuition = {
            tutorId: req.user._id,
            title: data.title,
            description: data.description,
            subject: data.subject,
            classLevel: data.classLevel,
            mode: data.mode,
            location: data.location,
            monthlyFee: fee,
            price: fee,
            daysPerWeek: data.daysPerWeek,
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
            .collection('tuitions')
            .insertOne(tuition);
        const inserted = await getDb().collection('tuitions').findOne({ _id: result.insertedId });
        res.status(201).json({ tuition: inserted });
    }
    catch (error) {
        next(error);
    }
});
/** Tutor updates own tuition. */
app.patch('/api/tuitions/:id', verifyToken, async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'tutor') {
            res.status(403).json({ message: 'Only tutors can edit tuitions' });
            return;
        }
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
            res.status(400).json({ message: 'Invalid tuition id' });
            return;
        }
        const tuition = await getDb()
            .collection('tuitions')
            .findOne({ _id: new ObjectId(id) });
        if (!tuition) {
            res.status(404).json({ message: 'Tuition not found' });
            return;
        }
        if (!tuition.tutorId.equals(req.user._id)) {
            res.status(403).json({ message: 'You do not own this tuition' });
            return;
        }
        if (tuition.approvalStatus === TuitionApprovalStatus.APPROVED || tuition.status === TuitionStatus.APPROVED) {
            res.status(403).json({ message: 'Approved tuitions can only be edited by admin' });
            return;
        }
        const partialSchema = z.object({
            title: z.string().min(1).optional(),
            description: z.string().min(1).optional(),
            subject: z.string().optional(),
            classLevel: z.string().optional(),
            mode: z.enum(['online', 'offline', 'hybrid']).optional(),
            location: z.string().optional(),
            monthlyFee: z.number().nonnegative().optional(),
            price: z.number().nonnegative().optional(),
            daysPerWeek: z.number().int().positive().optional(),
            bannerImage: z.string().optional(),
            active: z.boolean().optional(),
        });
        const parseResult = partialSchema.safeParse(req.body);
        if (!parseResult.success) {
            res.status(400).json({ message: 'Invalid tuition update', issues: parseResult.error.issues });
            return;
        }
        const update = parseResult.data;
        if (update.price !== undefined && update.monthlyFee === undefined) {
            update.monthlyFee = update.price;
        }
        else if (update.monthlyFee !== undefined && update.price === undefined) {
            update.price = update.monthlyFee;
        }
        if (update.active !== undefined) {
            update.isActive = update.active;
        }
        await getDb()
            .collection('tuitions')
            .updateOne({ _id: new ObjectId(id) }, { $set: update, $currentDate: { updatedAt: true } });
        const refreshed = await getDb()
            .collection('tuitions')
            .findOne({ _id: new ObjectId(id) });
        res.json({ tuition: refreshed });
    }
    catch (error) {
        next(error);
    }
});
/** Tutor deletes own tuition. */
app.delete('/api/tuitions/:id', verifyToken, async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'tutor') {
            res.status(403).json({ message: 'Only tutors can delete tuitions' });
            return;
        }
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
            res.status(400).json({ message: 'Invalid tuition id' });
            return;
        }
        const tuition = await getDb()
            .collection('tuitions')
            .findOne({ _id: new ObjectId(id) });
        if (!tuition) {
            res.status(404).json({ message: 'Tuition not found' });
            return;
        }
        if (!tuition.tutorId.equals(req.user._id)) {
            res.status(403).json({ message: 'You do not own this tuition' });
            return;
        }
        await getDb()
            .collection('tuitions')
            .deleteOne({ _id: new ObjectId(id) });
        res.json({ message: 'Tuition deleted' });
    }
    catch (error) {
        next(error);
    }
});
/** Admin changes tuition approval status (supports both /api/tuitions/:id/status and /api/admin/tuitions/:id/approval) */
app.patch(['/api/tuitions/:id/status', '/api/admin/tuitions/:id/approval'], verifyToken, async (req, res, next) => {
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
            res.status(400).json({ message: 'Invalid status', issues: parseResult.error.issues });
            return;
        }
        const newStatus = parseResult.data.approvalStatus ?? parseResult.data.status;
        const result = await getDb()
            .collection('tuitions')
            .updateOne({ _id: new ObjectId(id) }, {
            $set: {
                approvalStatus: newStatus,
                status: newStatus,
            },
            $currentDate: { updatedAt: true },
        });
        if (result.matchedCount === 0) {
            res.status(404).json({ message: 'Tuition not found' });
            return;
        }
        const refreshed = await getDb()
            .collection('tuitions')
            .findOne({ _id: new ObjectId(id) });
        res.json({ tuition: refreshed });
    }
    catch (error) {
        next(error);
    }
});
// ---------------------------------------------------------------------------
// 9. Application APIs (student & tutor)
// ---------------------------------------------------------------------------
/** Schema for creating an application. */
const applicationCreateSchema = z.object({
    tuitionId: z.string(),
    preferredSchedule: z.string().optional(),
    studentNote: z.string().optional(),
    message: z.string().optional(),
});
/** Student creates a new application. */
app.post('/api/applications', verifyToken, async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'student') {
            res.status(403).json({ message: 'Only students can apply' });
            return;
        }
        const parseResult = applicationCreateSchema.safeParse(req.body);
        if (!parseResult.success) {
            res.status(400).json({ message: 'Invalid application data', issues: parseResult.error.issues });
            return;
        }
        const { tuitionId, preferredSchedule, studentNote, message } = parseResult.data;
        if (!ObjectId.isValid(tuitionId)) {
            res.status(400).json({ message: 'Invalid tuition id' });
            return;
        }
        const tuition = await getDb()
            .collection('tuitions')
            .findOne({
            _id: new ObjectId(tuitionId),
            $or: [
                { approvalStatus: TuitionApprovalStatus.APPROVED },
                { status: TuitionStatus.APPROVED },
            ],
            $and: [
                {
                    $or: [{ isActive: true }, { active: true }],
                },
            ],
        });
        if (!tuition) {
            res.status(404).json({ message: 'Tuition not found or not open for applications' });
            return;
        }
        const existing = await getDb()
            .collection('applications')
            .findOne({
            tuitionId: new ObjectId(tuitionId),
            $or: [{ studentId: req.user._id }, { studentEmail: req.user.email }],
        });
        if (existing) {
            res.status(409).json({ message: 'Application already exists for this tuition' });
            return;
        }
        const appDoc = {
            tuitionId: new ObjectId(tuitionId),
            tuitionTitle: tuition.title,
            subject: tuition.subject,
            monthlyFee: tuition.monthlyFee ?? tuition.price ?? 0,
            tutorEmail: tuition.tutorEmail,
            studentId: req.user._id,
            studentName: req.user.name ?? '',
            studentEmail: req.user.email,
            studentPhone: req.user.phone,
            preferredSchedule,
            studentNote: studentNote || message,
            status: ApplicationStatus.PENDING,
            appliedAt: new Date(),
        };
        const result = await getDb()
            .collection('applications')
            .insertOne(appDoc);
        const inserted = await getDb().collection('applications').findOne({ _id: result.insertedId });
        res.status(201).json({ application: inserted });
    }
    catch (error) {
        next(error);
    }
});
/** Student views own applications. Supports both /api/applications/my and /api/applications/my-applications */
app.get(['/api/applications/my', '/api/applications/my-applications'], verifyToken, async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'student') {
            res.status(403).json({ message: 'Only students have a My Applications view' });
            return;
        }
        const apps = await getDb()
            .collection('applications')
            .find({
            $or: [{ studentId: req.user._id }, { studentEmail: req.user.email }],
        })
            .toArray();
        res.json({ applications: apps });
    }
    catch (error) {
        next(error);
    }
});
/** Tutor views applications for their tuitions. Enriches data for dashboard & list views */
app.get('/api/applications/tutor', verifyToken, async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'tutor') {
            res.status(403).json({ message: 'Only tutors can view applications to their tuitions' });
            return;
        }
        const db = getDb();
        const tutorTuitions = await db
            .collection('tuitions')
            .find({ tutorId: req.user._id })
            .toArray();
        const tuitionMap = new Map(tutorTuitions.map((t) => [t._id.toString(), t]));
        const tuitionIds = tutorTuitions.map((t) => t._id);
        const apps = await db
            .collection('applications')
            .find({ tuitionId: { $in: tuitionIds } })
            .toArray();
        const studentEmails = [...new Set(apps.map((a) => a.studentEmail).filter(Boolean))];
        const students = await db
            .collection('users')
            .find({ email: { $in: studentEmails } })
            .toArray();
        const studentMap = new Map(students.map((s) => [s.email, s]));
        const enrichedApps = apps.map((app) => {
            const tuition = tuitionMap.get(app.tuitionId.toString());
            const student = studentMap.get(app.studentEmail);
            return {
                ...app,
                student: {
                    name: app.studentName || student?.name || 'Unknown Student',
                    email: app.studentEmail,
                    phone: app.studentPhone || student?.phone,
                    avatar: student?.image,
                },
                tuition: {
                    _id: app.tuitionId,
                    title: app.tuitionTitle || tuition?.title || 'Tuition',
                    subject: app.subject || tuition?.subject || 'Subject',
                    location: tuition?.location || 'Location not specified',
                    monthlyFee: app.monthlyFee || tuition?.monthlyFee || tuition?.price,
                },
                createdAt: app.appliedAt || app.createdAt || new Date(),
            };
        });
        res.json({ applications: enrichedApps });
    }
    catch (error) {
        next(error);
    }
});
/** Tutor updates application status (accept/reject). */
app.patch('/api/applications/:id/status', verifyToken, async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'tutor') {
            res.status(403).json({ message: 'Only tutors can change application status' });
            return;
        }
        const appId = req.params.id;
        if (!ObjectId.isValid(appId)) {
            res.status(400).json({ message: 'Invalid application id' });
            return;
        }
        const statusSchema = z.object({
            status: z.enum([ApplicationStatus.ACCEPTED, ApplicationStatus.REJECTED]),
        });
        const parseResult = statusSchema.safeParse(req.body);
        if (!parseResult.success) {
            res.status(400).json({ message: 'Invalid status', issues: parseResult.error.issues });
            return;
        }
        const application = await getDb()
            .collection('applications')
            .findOne({ _id: new ObjectId(appId) });
        if (!application) {
            res.status(404).json({ message: 'Application not found' });
            return;
        }
        const tuition = await getDb().collection('tuitions').findOne({ _id: application.tuitionId });
        if (!tuition || (!tuition.tutorId.equals(req.user._id) && tuition.tutorEmail !== req.user.email)) {
            res.status(403).json({ message: 'You do not own this application' });
            return;
        }
        await getDb()
            .collection('applications')
            .updateOne({ _id: new ObjectId(appId) }, { $set: { status: parseResult.data.status }, $currentDate: { updatedAt: true } });
        const refreshed = await getDb()
            .collection('applications')
            .findOne({ _id: new ObjectId(appId) });
        res.json({ application: refreshed });
    }
    catch (error) {
        next(error);
    }
});
/** Student cancels (deletes) a pending application. */
app.delete('/api/applications/:id', verifyToken, async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'student') {
            res.status(403).json({ message: 'Only students can delete applications' });
            return;
        }
        const appId = req.params.id;
        if (!ObjectId.isValid(appId)) {
            res.status(400).json({ message: 'Invalid application id' });
            return;
        }
        const application = await getDb()
            .collection('applications')
            .findOne({ _id: new ObjectId(appId) });
        if (!application) {
            res.status(404).json({ message: 'Application not found' });
            return;
        }
        const isOwner = (application.studentId && application.studentId.equals(req.user._id)) ||
            application.studentEmail === req.user.email;
        if (!isOwner) {
            res.status(403).json({ message: 'You do not own this application' });
            return;
        }
        if (application.status !== ApplicationStatus.PENDING) {
            res.status(400).json({ message: 'Only pending applications can be canceled' });
            return;
        }
        await getDb()
            .collection('applications')
            .deleteOne({ _id: new ObjectId(appId) });
        res.json({ message: 'Application canceled' });
    }
    catch (error) {
        next(error);
    }
});
// ---------------------------------------------------------------------------
// 10. Dashboard APIs (role‑based)
// ---------------------------------------------------------------------------
/** Student dashboard – aggregated stats for the logged‑in student */
app.get('/api/dashboard/student', verifyToken, async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'student') {
            res.status(403).json({ message: 'Student access required' });
            return;
        }
        const studentEmail = req.user.email;
        const studentId = req.user._id;
        const applicationsColl = getDb().collection('applications');
        const tuitionColl = getDb().collection('tuitions');
        const studentFilter = {
            $or: [{ studentEmail }, { studentId }],
        };
        const [total, pending, accepted, rejected] = await Promise.all([
            applicationsColl.countDocuments(studentFilter),
            applicationsColl.countDocuments({ ...studentFilter, status: ApplicationStatus.PENDING }),
            applicationsColl.countDocuments({ ...studentFilter, status: ApplicationStatus.ACCEPTED }),
            applicationsColl.countDocuments({ ...studentFilter, status: ApplicationStatus.REJECTED }),
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
    }
    catch (error) {
        next(error);
    }
});
/** Tutor dashboard – aggregated stats for the logged‑in tutor */
app.get('/api/dashboard/tutor', verifyToken, async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'tutor') {
            res.status(403).json({ message: 'Tutor access required' });
            return;
        }
        const tutorId = req.user._id;
        const tuitionColl = getDb().collection('tuitions');
        const applicationColl = getDb().collection('applications');
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
                    { isActive: true, approvalStatus: TuitionApprovalStatus.APPROVED },
                    { active: true, status: TuitionStatus.APPROVED },
                ],
            }),
        ]);
        const tutorTuitions = await tuitionColl
            .find({ tutorId }, { projection: { _id: 1, title: 1, subject: 1 } })
            .toArray();
        const tuitionIds = tutorTuitions.map((t) => t._id);
        const [totalApplicants, pendingApplicants, acceptedApplicants] = await Promise.all([
            applicationColl.countDocuments({ tuitionId: { $in: tuitionIds } }),
            applicationColl.countDocuments({ tuitionId: { $in: tuitionIds }, status: ApplicationStatus.PENDING }),
            applicationColl.countDocuments({ tuitionId: { $in: tuitionIds }, status: ApplicationStatus.ACCEPTED }),
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
    }
    catch (error) {
        next(error);
    }
});
/** Admin dashboard – system‑wide aggregated statistics */
app.get('/api/dashboard/admin', verifyToken, async (req, res, next) => {
    try {
        if (req.user?.role !== 'admin') {
            res.status(403).json({ message: 'Admin access required' });
            return;
        }
        const db = getDb();
        const usersColl = db.collection('users');
        const tuitionsColl = db.collection('tuitions');
        const applicationsColl = db.collection('applications');
        const paymentsColl = db.collection('payments');
        const [totalUsers, studentCount, tutorCount, adminCount] = await Promise.all([
            usersColl.countDocuments({}),
            usersColl.countDocuments({ role: 'student' }),
            usersColl.countDocuments({ role: 'tutor' }),
            usersColl.countDocuments({ role: 'admin' }),
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
        const paymentAgg = await paymentsColl
            .aggregate([
            { $match: { paymentStatus: 'paid' } },
            { $group: { _id: null, totalRevenue: { $sum: '$amount' }, count: { $sum: 1 } } },
        ])
            .toArray();
        const paymentStats = paymentAgg[0] || { totalRevenue: 0, count: 0 };
        const recentUsers = await usersColl.find({}).sort({ createdAt: -1 }).limit(5).toArray();
        const recentTuitions = await tuitionsColl.find({}).sort({ createdAt: -1 }).limit(5).toArray();
        const recentPayments = await paymentsColl.find({ paymentStatus: 'paid' }).sort({ paidAt: -1 }).limit(5).toArray();
        res.json({
            users: {
                total: totalUsers,
                studentCount,
                tutorCount,
                adminCount,
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
            payments: {
                totalPaid: paymentStats.count,
                totalRevenue: paymentStats.totalRevenue,
                recent: recentPayments,
            },
            stats: {
                totalUsers,
                studentCount,
                tutorCount,
                adminCount,
                totalTuitions,
                pendingTuitions,
                approvedTuitions,
                rejectedTuitions,
                totalApplications,
                totalRevenue: paymentStats.totalRevenue,
                paidCount: paymentStats.count,
            },
            recentUsers,
            recentTuitions,
            recentPayments,
        });
    }
    catch (error) {
        next(error);
    }
});
// ---------------------------------------------------------------------------
// 11. 404 & Error handling
// ---------------------------------------------------------------------------
// Unknown routes return structured JSON instead of HTML
app.use((req, res) => {
    res.status(404).json({
        message: `Route not found: ${req.method} ${req.originalUrl}`,
    });
});
// Global error handler
const errorHandler = (err, _req, res, next) => {
    console.error('[server error]', err);
    if (res.headersSent) {
        return next(err);
    }
    const statusCode = typeof err?.statusCode === 'number' && err.statusCode >= 400 && err.statusCode < 600
        ? err.statusCode
        : 500;
    res.status(statusCode).json({
        message: IS_PRODUCTION ? 'Internal server error' : err?.message || 'Internal server error',
    });
};
app.use(errorHandler);
// ---------------------------------------------------------------------------
// 12. Server startup & shutdown handling
// ---------------------------------------------------------------------------
let server = null;
async function startServer() {
    await connectToDatabase();
    const db = getDb();
    // Safe indexing
    try {
        await Promise.all([
            db.collection('applications').createIndex({ tuitionId: 1, studentId: 1 }, { background: true }),
            db.collection('tuitions').createIndex({ tutorId: 1 }, { background: true }),
            db.collection('tuitions').createIndex({ approvalStatus: 1, isActive: 1 }, { background: true }),
        ]);
    }
    catch (indexError) {
        console.warn('[server] Warning initializing indexes:', indexError);
    }
    // Initialise BetterAuth after DB is connected
    authNodeHandler = toNodeHandler(getAuth());
    server = app.listen(env.port, () => {
        console.log(`[server] MentorLagbe API listening on http://localhost:${env.port}`);
    });
}
function handleShutdown(signal) {
    console.log(`[server] Received ${signal}. Shutting down gracefully...`);
    if (server) {
        server.close(() => {
            console.log('[server] HTTP server closed.');
            process.exit(0);
        });
    }
    else {
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
startServer().catch((error) => {
    console.error('[server] Failed to start:', error);
    process.exit(1);
});
export default app;
