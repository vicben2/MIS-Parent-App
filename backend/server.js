const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const nodemailer = require('nodemailer');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Railway PostgreSQL Connection Pool Configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false'
    ? false
    : process.env.DATABASE_URL
      ? { rejectUnauthorized: false }
      : false
});

const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'data', 'uploads');
const OTP_TTL_MINUTES = Number(process.env.OTP_TTL_MINUTES || 15);
const OTP_SECRET = process.env.OTP_SECRET || process.env.JWT_SECRET || 'mis-parent-app-prod-secret';

// System Constants
const APP_VERSION_CODE = Number(process.env.APP_VERSION_CODE || 2);
const APP_VERSION_NAME = process.env.APP_VERSION_NAME || '1.0.1';
const APP_APK_URL = process.env.APP_APK_URL || '';
const APP_RELEASE_NOTES = process.env.APP_RELEASE_NOTES || 'Production release.';

// Ensure upload directory exists
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/media/uploads', express.static(UPLOAD_DIR));

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_APP_PASSWORD || process.env.EMAIL_PASS,
  },
});

/**
 * Global Async Wrapper for Routes
 */
function asyncHandler(handler) {
    return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

// ==========================================
// SYSTEM & HEALTH ENDPOINTS
// ==========================================

app.get('/api/health', asyncHandler(async (req, res) => {
    // Basic connectivity check
    await pool.query('SELECT 1');
    res.json({ status: "healthy", database: "postgres", timestamp: new Date().toISOString() });
}));

app.get('/api/app/version', (req, res) => {
    res.json({
        latestVersionCode: APP_VERSION_CODE,
        latestVersionName: APP_VERSION_NAME,
        remarks: APP_RELEASE_NOTES,
        downloadUrl: APP_APK_URL
    });
});

// ==========================================
// FEEDBACK ENDPOINTS
// ==========================================

app.post('/api/feedback', asyncHandler(async (req, res) => {
    const { userEmail, feedbackType, message, deviceInfo, appVersion } = req.body;

    if (!feedbackType || !message) {
        return res.status(400).json({ error: "Feedback type and message are required." });
    }

    const phTimestamp = new Date().toLocaleString("en-US", { timeZone: "Asia/Manila" });
    const query = `
        INSERT INTO parent_app_feedback (user_email, feedback_type, message, app_version, created_at)
        VALUES ($1, $2, $3, $4, $5) RETURNING id;
    `;
    const values = [userEmail, feedbackType, message, deviceInfo || appVersion || APP_VERSION_NAME, phTimestamp];

    const result = await pool.query(query, values);
    res.status(201).json({ success: true, message: "Feedback stored.", feedbackId: result.rows[0].id });
}));

// ==========================================
// AUTHENTICATION ENDPOINTS
// ==========================================

app.post('/api/auth/login', asyncHandler(async (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const account = await get(
        `SELECT * FROM parent_accounts WHERE LOWER(username) = LOWER($1) AND password = $2`,
        [String(username).trim(), password]
    );

    if (!account) return res.status(401).json({ error: 'Invalid credentials' });

    const parent = await getParent(account.parent_id);
    const parentRow = await get('SELECT two_factor_enabled FROM parents WHERE id = $1', [account.parent_id]);

    if (parentRow?.two_factor_enabled) {
        const otp = await issueLoginOtp(parent);
        return res.json({ requiresTwoFactor: true, ...otp, parent });
    }

    const dashboard = await buildDashboard(account.parent_id);
    res.json({
        requiresTwoFactor: false,
        token: `session-${crypto.randomBytes(16).toString('hex')}`,
        parent,
        dashboard
    });
}));

app.post('/api/auth/verify-otp', asyncHandler(async (req, res) => {
    const { otpToken, code } = req.body || {};
    const otp = await get('SELECT * FROM login_otps WHERE id = $1', [otpToken]);

    if (!otp || otp.used || new Date(otp.expires_at) < Date.now()) {
        return res.status(401).json({ error: 'Invalid or expired code' });
    }

    if (hashOtp(String(code).trim()) !== otp.code_hash) {
        await run('UPDATE login_otps SET attempts = attempts + 1 WHERE id = $1', [otp.id]);
        return res.status(401).json({ error: 'Invalid code' });
    }

    await run('UPDATE login_otps SET used = 1 WHERE id = $1', [otp.id]);
    const parent = await getParent(otp.parent_id);
    const dashboard = await buildDashboard(otp.parent_id);
    res.json({ requiresTwoFactor: false, token: `session-${crypto.randomBytes(16).toString('hex')}`, parent, dashboard });
}));

app.post('/api/auth/resend-otp', asyncHandler(async (req, res) => {
    const { otpToken } = req.body || {};
    const currentOtp = await get('SELECT * FROM login_otps WHERE id = $1', [otpToken]);

    if (!currentOtp || currentOtp.used) {
        return res.status(401).json({ error: 'Invalid or expired verification code' });
    }

    const parent = await getParent(currentOtp.parent_id);
    try {
        await run('UPDATE login_otps SET used = 1 WHERE id = $1', [currentOtp.id]);
        const otp = await issueLoginOtp(parent);
        return res.json({ ...otp });
    } catch (error) {
        return res.status(503).json({ error: error.message });
    }
}));

// ==========================================
// DATA ACCESS ENDPOINTS
// ==========================================

app.get('/api/parent/dashboard', asyncHandler(async (req, res) => {
    const parentId = Number(req.query.parentId);
    if (!parentId) return res.status(400).json({ error: 'parentId required' });
    const dashboard = await buildDashboard(parentId);
    res.json(dashboard);
}));

app.get('/api/parent/security', asyncHandler(async (req, res) => {
    const parentId = Number(req.query.parentId || 1);
    const parent = await get('SELECT id, email, phone, two_factor_enabled FROM parents WHERE id = $1', [parentId]);
    if (!parent) return res.status(404).json({ error: 'Parent not found' });
    res.json({
        parentId: parent.id,
        email: parent.email,
        phone: parent.phone,
        twoFactorEnabled: Boolean(parent.two_factor_enabled)
    });
}));

app.patch('/api/parent/security', asyncHandler(async (req, res) => {
    const parentId = Number(req.body?.parentId || 1);
    const enabled = req.body?.twoFactorEnabled ? 1 : 0;
    const updated = await get(
        `UPDATE parents SET two_factor_enabled = $1 WHERE id = $2 RETURNING id, email, phone, two_factor_enabled`,
        [enabled, parentId]
    );
    if (!updated) return res.status(404).json({ error: 'Parent not found' });
    res.json({
        parentId: updated.id,
        email: updated.email,
        phone: updated.phone,
        twoFactorEnabled: Boolean(updated.two_factor_enabled)
    });
}));

app.get('/api/notifications', asyncHandler(async (req, res) => {
    const studentId = req.query.studentId ? Number(req.query.studentId) : null;
    const rows = await all(
        `SELECT * FROM notifications WHERE student_id IS NULL OR student_id = $1 ORDER BY is_new DESC, id DESC`,
        [studentId]
    );
    res.json(rows.map(item => ({
        id: item.id,
        studentId: item.student_id,
        text: item.text,
        type: item.type,
        time: item.time,
        category: item.category,
        isNew: Boolean(item.is_new),
        imageUrl: item.image_url || '',
        isPositive: Boolean(item.is_positive)
    })));
}));

app.get('/api/calendar', asyncHandler(async (req, res) => {
    const studentId = req.query.studentId ? Number(req.query.studentId) : null;
    const rows = await all(
        `SELECT * FROM calendar_events WHERE student_id IS NULL OR student_id = $1 ORDER BY date ASC, time ASC`,
        [studentId]
    );
    res.json(rows.map(item => ({
        id: item.id,
        title: item.title,
        category: item.category,
        date: item.date,
        time: item.time || "",
        description: item.description,
        eventType: item.category,
        status: item.status || "Normal",
        imageUrl: item.image_url || ""
    })));
}));

app.get('/api/student/:id/attendance', asyncHandler(async (req, res) => {
    const rows = await all('SELECT * FROM attendance_subjects WHERE student_id = $1 ORDER BY id', [req.params.id]);
    res.json(rows.map(mapAttendance));
}));

app.get('/api/student/:id/grades', asyncHandler(async (req, res) => {
    const rows = await all('SELECT * FROM academic_grades WHERE student_id = $1 ORDER BY id', [req.params.id]);
    res.json(rows.map(mapGrade));
}));

app.get('/api/student/:id/academic-performance', asyncHandler(async (req, res) => {
    const rows = await all('SELECT * FROM academic_performance WHERE student_id = $1 ORDER BY id', [req.params.id]);
    res.json(rows.map(mapAcademicPerformance));
}));

app.patch('/api/parent/profile', asyncHandler(async (req, res) => {
    const parentId = Number(req.body?.parentId);
    let profileImageUrl = req.body?.profileImageUrl;

    if (typeof req.body?.profileImageData === 'string' && req.body.profileImageData.trim() !== '') {
        profileImageUrl = saveBase64Image(req.body.profileImageData, req.body.profileImageMimeType, `parent-${parentId}`);
    }

    const updated = await get(
        `UPDATE parents SET email = COALESCE($1, email), phone = COALESCE($2, phone),
         profile_image_url = COALESCE($3, profile_image_url) WHERE id = $4 RETURNING id`,
        [nullableString(req.body?.email), nullableString(req.body?.phone), profileImageUrl, parentId]
    );
    res.json(await getParent(updated.id));
}));

// ==========================================
// DATABASE HELPERS & MAPPING
// ==========================================

function normalizeRow(row) {
    if (!row) return row;
    if (Object.prototype.hasOwnProperty.call(row, 'count')) row.count = Number(row.count);
    return row;
}

async function run(sql, params = []) { return pool.query(sql, params); }
async function get(sql, params = []) { const r = await pool.query(sql, params); return normalizeRow(r.rows[0]); }
async function all(sql, params = []) { const r = await pool.query(sql, params); return r.rows.map(normalizeRow); }

async function getParent(parentId) {
    const parent = await get('SELECT id, name, email, phone, profile_image_url, background_image_url FROM parents WHERE id = $1', [parentId]);
    if (!parent) return null;
    const children = await all('SELECT student_id FROM parent_students WHERE parent_id = $1', [parentId]);
    return {
        id: parent.id,
        name: parent.name,
        email: parent.email,
        phone: parent.phone,
        profileImageUrl: parent.profile_image_url,
        backgroundImageUrl: parent.background_image_url,
        children: children.map(c => c.student_id)
    };
}

async function getStudent(studentId) {
    const row = await get('SELECT * FROM students WHERE id = $1', [studentId]);
    if (!row) return null;

    const schedules = await all('SELECT * FROM class_schedules WHERE student_id = $1 ORDER BY day, start_time', [studentId]);
    const studyLoad = await all('SELECT * FROM study_load_subjects WHERE student_id = $1 ORDER BY sort_order', [studentId]);

    // Dynamic Performance Calculation
    const attendanceVal = parseFloat(row.attendance?.replace('%', '')) || 0;
    const gpaNormalized = row.gpa <= 3.0 ? 100 - (row.gpa - 1.0) * 12.5 : 75 - (row.gpa - 3.0) * 37.5;
    const performanceRows = await all('SELECT is_positive FROM academic_performance WHERE student_id = $1', [studentId]);
    const taskScore = performanceRows.length > 0 ? (performanceRows.filter(r => r.is_positive).length / performanceRows.length) * 100 : 100;

    const schoolUnread = await get('SELECT COUNT(*) FROM notifications WHERE is_new = 1 AND student_id IS NULL');
    const studentUnread = await get('SELECT COUNT(*) FROM notifications WHERE is_new = 1 AND student_id = $1', [studentId]);

    return {
        id: row.id,
        name: row.name,
        rollNumber: row.roll_number,
        grade: row.grade,
        section: row.section,
        program: row.program,
        course: row.course,
        year: row.year,
        classTeacher: row.class_teacher,
        attendance: row.attendance,
        gpa: row.gpa,
        pendingPayments: row.pending_payments,
        profileImageUrl: row.profile_image_url,
        backgroundImageUrl: row.background_image_url,
        notificationCount: Number(schoolUnread.count || 0) + Number(studentUnread.count || 0),
        performancePercentage: Math.round((gpaNormalized * 0.6) + (attendanceVal * 0.3) + (taskScore * 0.1)),
        schedules: schedules.map(s => ({
            subject: s.subject,
            room: s.room,
            instructor: s.instructor,
            day: s.day,
            startTime: s.start_time,
            endTime: s.end_time
        })),
        studyLoad: studyLoad.map(l => ({
            scheduleNumber: l.schedule_number,
            courseNumber: l.course_number,
            code: l.code,
            title: l.title,
            units: l.units,
            instructor: l.instructor,
            schedule: l.schedule,
            time: l.time,
            days: l.days,
            room: l.room,
            remarks: l.remarks,
            semester: l.semester,
            schoolYear: l.school_year,
            dateEnrolled: l.date_enrolled
        }))
    };
}

async function buildDashboard(parentId) {
    const parent = await getParent(parentId);
    if (!parent) return null;

    const children = (await Promise.all(parent.children.map(id => getStudent(id)))).filter(Boolean);
    const totalUnread = await get('SELECT COUNT(*) FROM notifications WHERE is_new = 1 AND (student_id IS NULL OR student_id = ANY($1))', [parent.children]);

    return {
        parent,
        children,
        unreadAnnouncements: Number(totalUnread.count || 0)
    };
}

async function issueLoginOtp(parent) {
    const code = String(crypto.randomInt(100000, 999999));
    const otpId = crypto.randomBytes(24).toString('hex');
    const expiresAt = new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000).toISOString();

    await run('INSERT INTO login_otps (id, parent_id, code_hash, expires_at) VALUES ($1, $2, $3, $4)', [otpId, parent.id, hashOtp(code), expiresAt]);

    await transporter.sendMail({
        from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
        to: parent.email,
        subject: 'Verification Code',
        text: `Your code is ${code}. It expires in ${OTP_TTL_MINUTES} minutes.`
    });

    return { otpToken: otpId, email: parent.email.replace(/(..)(.*)(@.*)/, '$1***$3'), expiresAt };
}

function hashOtp(code) { return crypto.createHash('sha256').update(`${code}:${OTP_SECRET}`).digest('hex'); }

function mapGrade(r) { return { id: r.id, studentId: r.student_id, subjectName: r.subject_name, units: r.units, grade: r.grade, instructor: r.instructor, remarks: r.remarks, term: r.term }; }
function mapAttendance(r) { return { id: r.id, studentId: r.student_id, subjectName: r.subject_name, instructor: r.instructor, presentDays: r.present_days, totalDays: r.total_days, lateDays: r.late_days, absentDays: r.absent_days }; }
function mapAcademicPerformance(r) { return { id: r.id, studentId: r.student_id, type: r.type, title: r.title, subject: r.subject, teacher: r.teacher, summary: r.summary, details: r.details, criteria: r.criteria, imageUrl: r.image_url, score: r.score, status: r.status, assignedDate: r.assigned_date, dueDate: r.due_date, timeAgo: r.time_ago, isPositive: Boolean(r.is_positive) }; }

function saveBase64Image(base64Data, mimeType, prefix) {
    const ext = mimeType.includes('png') ? 'png' : 'jpg';
    const name = `${prefix}-${Date.now()}.${ext}`;
    fs.writeFileSync(path.join(UPLOAD_DIR, name), Buffer.from(base64Data, 'base64'));
    return `/media/uploads/${name}`;
}

function nullableString(v) { return (v === undefined || v === null) ? null : String(v).trim(); }

// ==========================================
// STARTUP & INITIALIZATION
// ==========================================

async function initDatabase() {
    console.log("Checking database schema...");

    // 1. parents
    await pool.query(`
        CREATE TABLE IF NOT EXISTS parents (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            profile_image_url TEXT NOT NULL DEFAULT '',
            background_image_url TEXT NOT NULL DEFAULT '',
            two_factor_enabled INTEGER NOT NULL DEFAULT 0
        );
    `);

    // 2. parent_accounts
    await pool.query(`
        CREATE TABLE IF NOT EXISTS parent_accounts (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            parent_id INTEGER NOT NULL REFERENCES parents(id)
        );
    `);

    // 3. login_otps
    await pool.query(`
        CREATE TABLE IF NOT EXISTS login_otps (
            id TEXT PRIMARY KEY,
            parent_id INTEGER NOT NULL REFERENCES parents(id),
            code_hash TEXT NOT NULL,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    `);

    // 4. students
    await pool.query(`
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            roll_number TEXT NOT NULL,
            grade TEXT NOT NULL,
            section TEXT NOT NULL,
            program TEXT NOT NULL,
            course TEXT NOT NULL,
            year TEXT NOT NULL,
            class_teacher TEXT NOT NULL,
            attendance TEXT NOT NULL,
            gpa DOUBLE PRECISION NOT NULL,
            pending_payments INTEGER NOT NULL DEFAULT 0,
            profile_image_url TEXT NOT NULL DEFAULT '',
            background_image_url TEXT NOT NULL DEFAULT ''
        );
    `);

    // 5. parent_students (junction)
    await pool.query(`
        CREATE TABLE IF NOT EXISTS parent_students (
            parent_id INTEGER NOT NULL REFERENCES parents(id),
            student_id INTEGER NOT NULL REFERENCES students(id),
            PRIMARY KEY(parent_id, student_id)
        );
    `);

    // 6. academic_performance
    await pool.query(`
        CREATE TABLE IF NOT EXISTS academic_performance (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES students(id),
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            subject TEXT NOT NULL,
            teacher TEXT NOT NULL,
            summary TEXT NOT NULL,
            details TEXT NOT NULL,
            criteria TEXT NOT NULL,
            image_url TEXT,
            score TEXT,
            status TEXT NOT NULL,
            assigned_date TEXT NOT NULL,
            due_date TEXT NOT NULL,
            time_ago TEXT NOT NULL,
            is_positive BOOLEAN NOT NULL DEFAULT TRUE
        );
    `);

    // 7. notifications
    await pool.query(`
        CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY,
            student_id INTEGER REFERENCES students(id),
            text TEXT NOT NULL,
            type TEXT NOT NULL,
            time TEXT NOT NULL,
            category TEXT NOT NULL,
            is_new INTEGER NOT NULL DEFAULT 0,
            image_url TEXT NOT NULL DEFAULT '',
            is_positive INTEGER NOT NULL DEFAULT 1
        );
    `);

    // 8. feedback
    await pool.query(`
        CREATE TABLE IF NOT EXISTS parent_app_feedback (
            id SERIAL PRIMARY KEY,
            user_email TEXT,
            feedback_type TEXT NOT NULL,
            message TEXT NOT NULL,
            app_version TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);

    console.log("Database initialized successfully.");
}

initDatabase().then(() => {
    app.listen(PORT, () => console.log(`MIS Backend running on port ${PORT}`));
}).catch(err => {
    console.error("Database initialization failed:", err);
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
});
