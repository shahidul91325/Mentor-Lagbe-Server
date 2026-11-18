import express from 'express';
import { connectDB, getDB } from './db.js';
import { ObjectId } from 'mongodb';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { z } from 'zod';
dotenv.config();
const app = express();
app.use(express.json());
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing token' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET || 'secret');
        req.user = payload;
        next();
    }
    catch (e) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};
// ----- Helper -----
const toObjectId = (id) => {
    const str = Array.isArray(id) ? id[0] : id;
    if (!ObjectId.isValid(str))
        throw new Error('Invalid id');
    return new ObjectId(str);
};
// ----- Indexes & DB Init -----
(async () => {
    const db = await connectDB();
    await db.collection('applications').createIndex({ tuitionId: 1, studentId: 1 }, { unique: true });
    await db.collection('tuitions').createIndex({ tutorId: 1 });
})();
// ----- Tuition Schemas -----
const tuitionCreateSchema = z.object({
    title: z.string().min(1),
    description: z.string().min(1),
    subject: z.string().min(1),
    price: z.number().nonnegative(),
});
const tuitionUpdateSchema = z.object({
    title: z.string().min(1).optional(),
    description: z.string().min(1).optional(),
    subject: z.string().min(1).optional(),
    price: z.number().nonnegative().optional(),
    active: z.boolean().optional(),
});
// ----- Tuition Routes -----
app.get('/api/tuitions', async (req, res) => {
    const db = getDB();
    const tuitions = await db
        .collection('tuitions')
        .find({ status: 'approved', active: true })
        .toArray();
    res.json(tuitions);
});
app.get('/api/tuitions/:id', async (req, res) => {
    const db = getDB();
    try {
        const tuition = await db
            .collection('tuitions')
            .findOne({ _id: toObjectId(req.params.id), status: 'approved', active: true });
        if (!tuition)
            return res.status(404).json({ error: 'Tuition not found' });
        res.json(tuition);
    }
    catch (e) {
        res.status(400).json({ error: 'Invalid id' });
    }
});
app.post('/api/tuitions', authMiddleware, async (req, res) => {
    const user = req.user;
    if (user.role !== 'tutor')
        return res.status(403).json({ error: 'Only tutors can create tuitions' });
    const parse = tuitionCreateSchema.safeParse(req.body);
    if (!parse.success)
        return res.status(400).json({ error: parse.error.format() });
    const db = getDB();
    // enforce free tutor limit
    if (user.plan !== 'pro') {
        const count = await db
            .collection('tuitions')
            .countDocuments({ tutorId: user._id });
        if (count >= 2) {
            return res.status(403).json({ error: 'Free tutors can create at most 2 tuition posts' });
        }
    }
    const now = new Date();
    const tuition = {
        tutorId: user._id,
        title: parse.data.title,
        description: parse.data.description,
        subject: parse.data.subject,
        price: parse.data.price,
        status: 'pending',
        active: true,
        createdAt: now,
        updatedAt: now,
    };
    const result = await db.collection('tuitions').insertOne(tuition);
    res.status(201).json({ _id: result.insertedId, ...tuition });
});
app.patch('/api/tuitions/:id', authMiddleware, async (req, res) => {
    const user = req.user;
    if (user.role !== 'tutor')
        return res.status(403).json({ error: 'Only tutors can edit tuitions' });
    const parse = tuitionUpdateSchema.safeParse(req.body);
    if (!parse.success)
        return res.status(400).json({ error: parse.error.format() });
    const db = getDB();
    try {
        const tuition = await db
            .collection('tuitions')
            .findOne({ _id: toObjectId(req.params.id) });
        if (!tuition)
            return res.status(404).json({ error: 'Tuition not found' });
        if (tuition.tutorId !== user._id)
            return res.status(403).json({ error: 'Not owner' });
        const update = { ...parse.data, updatedAt: new Date() };
        await db.collection('tuitions').updateOne({ _id: toObjectId(req.params.id) }, { $set: update });
        const updated = await db.collection('tuitions').findOne({ _id: toObjectId(req.params.id) });
        res.json(updated);
    }
    catch (e) {
        res.status(400).json({ error: 'Invalid id' });
    }
});
app.delete('/api/tuitions/:id', authMiddleware, async (req, res) => {
    const user = req.user;
    if (user.role !== 'tutor')
        return res.status(403).json({ error: 'Only tutors can delete tuitions' });
    const db = getDB();
    try {
        const tuition = await db
            .collection('tuitions')
            .findOne({ _id: toObjectId(req.params.id) });
        if (!tuition)
            return res.status(404).json({ error: 'Tuition not found' });
        if (tuition.tutorId !== user._id)
            return res.status(403).json({ error: 'Not owner' });
        await db.collection('tuitions').deleteOne({ _id: toObjectId(req.params.id) });
        res.status(204).send();
    }
    catch (e) {
        res.status(400).json({ error: 'Invalid id' });
    }
});
app.patch('/api/tuitions/:id/status', authMiddleware, async (req, res) => {
    const user = req.user;
    if (user.role !== 'admin')
        return res.status(403).json({ error: 'Only admin can change status' });
    const statusSchema = z.object({ status: z.enum(['approved', 'rejected']) });
    const parse = statusSchema.safeParse(req.body);
    if (!parse.success)
        return res.status(400).json({ error: parse.error.format() });
    const db = getDB();
    try {
        const result = await db
            .collection('tuitions')
            .findOneAndUpdate({ _id: toObjectId(req.params.id) }, { $set: { status: parse.data.status, updatedAt: new Date() } }, { returnDocument: 'after' });
        // result may be undefined if not found
        if (!result?.value)
            return res.status(404).json({ error: 'Tuition not found' });
        res.json(result.value);
    }
    catch (e) {
        res.status(400).json({ error: 'Invalid id' });
    }
});
// ----- Application Schemas -----
const applicationCreateSchema = z.object({
    tuitionId: z.string().min(1),
    message: z.string().optional(),
});
const applicationStatusSchema = z.object({ status: z.enum(['accepted', 'rejected']) });
// ----- Application Routes -----
app.post('/api/applications', authMiddleware, async (req, res) => {
    const user = req.user;
    if (user.role !== 'student')
        return res.status(403).json({ error: 'Only students can apply' });
    const parse = applicationCreateSchema.safeParse(req.body);
    if (!parse.success)
        return res.status(400).json({ error: parse.error.format() });
    const db = getDB();
    // Verify tuition exists and is approved & active
    const tuition = await db
        .collection('tuitions')
        .findOne({ _id: toObjectId(parse.data.tuitionId), status: 'approved', active: true });
    if (!tuition)
        return res.status(400).json({ error: 'Tuition not available' });
    const now = new Date();
    const appDoc = {
        tuitionId: parse.data.tuitionId,
        studentId: user._id,
        message: parse.data.message,
        status: 'pending',
        createdAt: now,
        updatedAt: now,
    };
    try {
        const result = await db.collection('applications').insertOne(appDoc);
        res.status(201).json({ _id: result.insertedId, ...appDoc });
    }
    catch (e) {
        if (e.code === 11000) {
            return res.status(409).json({ error: 'Duplicate application' });
        }
        throw e;
    }
});
app.get('/api/applications/my', authMiddleware, async (req, res) => {
    const user = req.user;
    if (user.role !== 'student')
        return res.status(403).json({ error: 'Only students' });
    const db = getDB();
    const apps = await db
        .collection('applications')
        .find({ studentId: user._id })
        .toArray();
    res.json(apps);
});
app.get('/api/applications/tutor', authMiddleware, async (req, res) => {
    const user = req.user;
    if (user.role !== 'tutor')
        return res.status(403).json({ error: 'Only tutors' });
    const db = getDB();
    const tuitions = await db
        .collection('tuitions')
        .find({ tutorId: user._id })
        .project({ _id: 1 })
        .toArray();
    const tuitionIds = tuitions.map(t => t._id.toString());
    const apps = await db
        .collection('applications')
        .find({ tuitionId: { $in: tuitionIds } })
        .toArray();
    res.json(apps);
});
app.patch('/api/applications/:id/status', authMiddleware, async (req, res) => {
    const user = req.user;
    if (user.role !== 'tutor')
        return res.status(403).json({ error: 'Only tutors can change status' });
    const parse = applicationStatusSchema.safeParse(req.body);
    if (!parse.success)
        return res.status(400).json({ error: parse.error.format() });
    const db = getDB();
    try {
        const app = await db
            .collection('applications')
            .findOne({ _id: toObjectId(req.params.id) });
        if (!app)
            return res.status(404).json({ error: 'Application not found' });
        // verify ownership via tuition
        const tuition = await db
            .collection('tuitions')
            .findOne({ _id: toObjectId(app.tuitionId) });
        if (!tuition || tuition.tutorId !== user._id)
            return res.status(403).json({ error: 'Not owner' });
        const result = await db
            .collection('applications')
            .findOneAndUpdate({ _id: app._id }, { $set: { status: parse.data.status, updatedAt: new Date() } }, { returnDocument: 'after' });
        res.json(result?.value);
    }
    catch (e) {
        res.status(400).json({ error: 'Invalid id' });
    }
});
app.delete('/api/applications/:id', authMiddleware, async (req, res) => {
    const user = req.user;
    if (user.role !== 'student')
        return res.status(403).json({ error: 'Only students can delete' });
    const db = getDB();
    try {
        const app = await db
            .collection('applications')
            .findOne({ _id: toObjectId(req.params.id) });
        if (!app)
            return res.status(404).json({ error: 'Application not found' });
        if (app.studentId !== user._id)
            return res.status(403).json({ error: 'Not owner' });
        if (app.status !== 'pending')
            return res.status(400).json({ error: 'Only pending applications can be cancelled' });
        await db.collection('applications').deleteOne({ _id: toObjectId(req.params.id) });
        res.status(204).send();
    }
    catch (e) {
        res.status(400).json({ error: 'Invalid id' });
    }
});
// ----- Start Server -----
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
