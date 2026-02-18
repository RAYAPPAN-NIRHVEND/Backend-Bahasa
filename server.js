// ============================================================================
// BACKEND API - Node.js + Express
// File: server.js
// ============================================================================

require('dotenv').config(); // Load .env variables

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// Middleware
// CORS Configuration - Allow Netlify frontend
const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'https://polyglotquest.netlify.app',
            'http://localhost:3001',
            'http://127.0.0.1:3001'
        ];
        
        if (allowedOrigins.indexOf(origin) !== -1 || origin.includes('netlify.app')) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));
app.use(express.json());

// Serve static files dari root folder (untuk admin.html)
app.use(express.static(__dirname));
// Serve uploads folder
app.use('/uploads', express.static('uploads'));
// Serve public folder (jika ada)
app.use(express.static('public'));

// File upload configuration
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage });

// Email configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'your-email@gmail.com',
        pass: process.env.EMAIL_PASS || 'your-app-password'
    }
});

// ============================================================================
// SIMPLE FILE-BASED DATABASE (Production: gunakan MongoDB/PostgreSQL)
// ============================================================================

const DB_DIR = './database';
const USERS_FILE = `${DB_DIR}/users.json`;
const PAYMENTS_FILE = `${DB_DIR}/payments.json`;
const PROGRESS_FILE = `${DB_DIR}/progress.json`;

// Initialize database
async function initDB() {
    try {
        await fs.mkdir(DB_DIR, { recursive: true });
        await fs.mkdir('./uploads', { recursive: true });
        
        // Initialize files if not exist
        try {
            await fs.access(USERS_FILE);
        } catch {
            await fs.writeFile(USERS_FILE, JSON.stringify([]));
        }
        
        try {
            await fs.access(PAYMENTS_FILE);
        } catch {
            await fs.writeFile(PAYMENTS_FILE, JSON.stringify([]));
        }
        
        try {
            await fs.access(PROGRESS_FILE);
        } catch {
            await fs.writeFile(PROGRESS_FILE, JSON.stringify({}));
        }
        
        console.log('✓ Database initialized');
    } catch (error) {
        console.error('Database initialization error:', error);
    }
}

// Database helpers
async function readDB(file) {
    try {
        const data = await fs.readFile(file, 'utf8');
        return JSON.parse(data);
    } catch {
        return file === PROGRESS_FILE ? {} : [];
    }
}

async function writeDB(file, data) {
    await fs.writeFile(file, JSON.stringify(data, null, 2));
}

// ============================================================================
// AUTHENTICATION
// ============================================================================

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;
        
        // Validation
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Semua field wajib diisi' });
        }
        
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Format email tidak valid' });
        }
        
        if (password.length < 8) {
            return res.status(400).json({ error: 'Password minimal 8 karakter' });
        }

        // Phone validation
        if (!phone) {
            return res.status(400).json({ error: 'No. ponsel wajib diisi' });
        }
        const phoneDigits = phone.replace(/[\s\-\+]/g, '');
        if (!/^\d{10,15}$/.test(phoneDigits)) {
            return res.status(400).json({ error: 'Format no. ponsel tidak valid' });
        }
        
        // Check if email exists
        const users = await readDB(USERS_FILE);
        if (users.find(u => u.email === email)) {
            return res.status(400).json({ error: 'Email sudah terdaftar' });
        }

        // Check if phone exists
        if (users.find(u => u.phone === phone)) {
            return res.status(400).json({ error: 'No. ponsel sudah terdaftar' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const newUser = {
            id: Date.now().toString(),
            name,
            email,
            phone,
            password: hashedPassword,
            freeTrials: 5,
            points: 0,
            createdAt: new Date().toISOString(),
            verified: true // Auto-verify untuk demo
        };
        
        users.push(newUser);
        await writeDB(USERS_FILE, users);
        
        // Send email to developer
        await sendEmailToAdmin('register', {
            name,
            email,
            phone,
            timestamp: new Date().toISOString()
        });
        
        res.json({ 
            message: 'Registrasi berhasil',
            user: {
                id: newUser.id,
                name: newUser.name,
                email: newUser.email,
                phone: newUser.phone
            }
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const users = await readDB(USERS_FILE);
        const user = users.find(u => u.email === email);
        
        if (!user) {
            return res.status(401).json({ error: 'Email tidak terdaftar' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Password salah' });
        }
        
        // Generate JWT token
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: '30d' }
        );
        
        res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                freeTrials: user.freeTrials,
                points: user.points
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
});

// Get user profile
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const users = await readDB(USERS_FILE);
        const user = users.find(u => u.id === req.userId);
        
        if (!user) {
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        res.json({
            id: user.id,
            name: user.name,
            email: user.email,
            freeTrials: user.freeTrials,
            points: user.points
        });
    } catch (error) {
        res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
});

// ============================================================================
// PROGRESS MANAGEMENT
// ============================================================================

// Get user progress
app.get('/api/progress', authenticateToken, async (req, res) => {
    try {
        const progress = await readDB(PROGRESS_FILE);
        res.json(progress[req.userId] || {});
    } catch (error) {
        res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
});

// Update progress
app.post('/api/progress', authenticateToken, async (req, res) => {
    try {
        const { languageId, difficultyId, level, score } = req.body;
        
        const progress = await readDB(PROGRESS_FILE);
        if (!progress[req.userId]) {
            progress[req.userId] = {};
        }
        
        const key = `${languageId}_${difficultyId}`;
        if (!progress[req.userId][key]) {
            progress[req.userId][key] = { level: 0, score: 0 };
        }
        
        progress[req.userId][key].level = Math.max(
            progress[req.userId][key].level,
            level
        );
        progress[req.userId][key].score += score;
        
        await writeDB(PROGRESS_FILE, progress);
        
        // Update user trials/points
        const users = await readDB(USERS_FILE);
        const userIndex = users.findIndex(u => u.id === req.userId);
        if (userIndex !== -1) {
            if (users[userIndex].freeTrials > 0) {
                users[userIndex].freeTrials--;
            } else if (users[userIndex].points > 0) {
                users[userIndex].points--;
            } else {
                return res.status(403).json({ error: 'Tidak ada trial atau poin tersisa' });
            }
            await writeDB(USERS_FILE, users);
        }
        
        res.json({ 
            message: 'Progress berhasil disimpan',
            progress: progress[req.userId]
        });
    } catch (error) {
        res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
});

// ============================================================================
// PAYMENT MANAGEMENT
// ============================================================================

// Create payment
app.post('/api/payments', authenticateToken, upload.single('proof'), async (req, res) => {
    try {
        const { packageId, method } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ error: 'Bukti transfer wajib diupload' });
        }
        
        const packages = {
            starter: { points: 50, price: 25000 },
            regular: { points: 100, price: 45000 },
            premium: { points: 200, price: 80000 },
            ultimate: { points: 500, price: 175000 }
        };
        
        const pkg = packages[packageId];
        if (!pkg) {
            return res.status(400).json({ error: 'Paket tidak valid' });
        }
        
        const users = await readDB(USERS_FILE);
        const user = users.find(u => u.id === req.userId);
        
        const payment = {
            id: Date.now().toString(),
            userId: req.userId,
            userName: user.name,
            userEmail: user.email,
            packageId,
            points: pkg.points,
            amount: pkg.price,
            method,
            proofImage: `/uploads/${req.file.filename}`,
            status: 'pending',
            createdAt: new Date().toISOString()
        };
        
        const payments = await readDB(PAYMENTS_FILE);
        payments.push(payment);
        await writeDB(PAYMENTS_FILE, payments);
        
        // Send email to developer
        await sendEmailToAdmin('payment', payment);
        
        res.json({ 
            message: 'Pembayaran berhasil disubmit. Menunggu verifikasi admin.',
            payment
        });
    } catch (error) {
        console.error('Payment error:', error);
        res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
});

// Get user payments
app.get('/api/payments/user', authenticateToken, async (req, res) => {
    try {
        const payments = await readDB(PAYMENTS_FILE);
        const userPayments = payments.filter(p => p.userId === req.userId);
        res.json(userPayments);
    } catch (error) {
        res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
});

// ============================================================================
// SUBMIT PAYMENT (User uploads proof, waits for admin approval)
// ============================================================================
app.post('/api/payment/submit', authenticateToken, upload.single('proof'), async (req, res) => {
    try {
        const { packageType, points, amount, method } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ error: 'Bukti transfer wajib diupload' });
        }
        
        // Validate package
        const validPackages = {
            single: { points: 300, price: 15000, name: 'Single Language (300 pts)' },
            full: { points: 2100, price: 49000, name: 'Full Access 7-in-1 (2,100 pts)' }
        };
        
        const pkg = validPackages[packageType];
        if (!pkg || pkg.points !== parseInt(points) || pkg.price !== parseInt(amount)) {
            return res.status(400).json({ error: 'Paket tidak valid' });
        }
        
        const users = await readDB(USERS_FILE);
        const user = users.find(u => u.id === req.userId);
        
        if (!user) {
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        // Create payment record with pending status
        const payment = {
            id: Date.now().toString(),
            userId: req.userId,
            userName: user.name,
            userEmail: user.email,
            packageType,
            packageName: pkg.name,
            points: parseInt(points),
            amount: parseInt(amount),
            method,
            proofImage: `/uploads/${req.file.filename}`,
            status: 'pending',
            createdAt: new Date().toISOString()
        };
        
        const payments = await readDB(PAYMENTS_FILE);
        payments.push(payment);
        await writeDB(PAYMENTS_FILE, payments);
        
        // Send notification email to admin
        try {
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: process.env.ADMIN_EMAIL,
                subject: '🔔 Pembayaran Baru - PolyglotQuest',
                html: `
                    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                        <h2 style="color:#f59e0b;">💳 Pembayaran Baru Menunggu Verifikasi</h2>
                        
                        <div style="background:#f3f4f6;padding:20px;border-radius:8px;margin:20px 0;">
                            <h3 style="margin-top:0;">Detail Pembayaran:</h3>
                            <p><strong>User:</strong> ${user.name} (${user.email})</p>
                            <p><strong>Paket:</strong> ${pkg.name}</p>
                            <p><strong>Points:</strong> ${points} 💎</p>
                            <p><strong>Total:</strong> Rp ${parseInt(amount).toLocaleString('id-ID')}</p>
                            <p><strong>Metode:</strong> ${method}</p>
                            <p><strong>Status:</strong> <span style="color:#f59e0b;font-weight:bold;">Pending</span></p>
                            <p><strong>Waktu:</strong> ${new Date().toLocaleString('id-ID')}</p>
                        </div>
                        
                        <p>Silakan cek bukti transfer dan approve/reject di admin panel.</p>
                        <p><a href="http://localhost:${PORT}/admin.html" style="background:#6366f1;color:white;padding:12px 24px;text-decoration:none;border-radius:8px;display:inline-block;">Buka Admin Panel</a></p>
                    </div>
                `
            });
        } catch (emailError) {
            console.error('Email error:', emailError);
        }
        
        // Send confirmation email to user
        try {
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: user.email,
                subject: '✅ Pembayaran Diterima - PolyglotQuest',
                html: `
                    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                        <h2 style="color:#10b981;">✅ Pembayaran Berhasil Diterima!</h2>
                        <p>Halo <strong>${user.name}</strong>,</p>
                        <p>Terima kasih! Pembayaran Anda telah kami terima dan sedang dalam proses verifikasi.</p>
                        
                        <div style="background:#f3f4f6;padding:20px;border-radius:8px;margin:20px 0;">
                            <h3 style="margin-top:0;">Detail Transaksi:</h3>
                            <p><strong>Paket:</strong> ${pkg.name}</p>
                            <p><strong>Points:</strong> ${points} 💎</p>
                            <p><strong>Total:</strong> Rp ${parseInt(amount).toLocaleString('id-ID')}</p>
                            <p><strong>Metode:</strong> ${method}</p>
                            <p><strong>Status:</strong> <span style="color:#f59e0b;font-weight:bold;">Menunggu Verifikasi</span></p>
                        </div>
                        
                        <div style="background:#fef3c7;border-left:4px solid #f59e0b;padding:12px;margin:20px 0;">
                            <p style="margin:0;"><strong>⏳ Proses Verifikasi:</strong></p>
                            <p style="margin:8px 0 0 0;">Admin akan memverifikasi pembayaran Anda dalam waktu 1x24 jam. Points akan otomatis masuk ke akun Anda setelah disetujui.</p>
                        </div>
                        
                        <p>Anda akan mendapat email notifikasi setelah pembayaran disetujui.</p>
                        <p style="margin-top:30px;color:#6b7280;font-size:14px;">
                            Terima kasih telah menggunakan PolyglotQuest!<br>
                            Happy Learning! 🌍
                        </p>
                    </div>
                `
            });
        } catch (emailError) {
            console.error('Email error:', emailError);
        }
        
        res.json({ 
            success: true,
            message: 'Pembayaran berhasil disubmit. Menunggu verifikasi admin.',
            payment
        });
        
    } catch (error) {
        console.error('Payment submission error:', error);
        res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
});

// ============================================================================
// ADMIN ENDPOINTS
// ============================================================================

// Get all pending payments (Admin only)
app.get('/api/admin/payments/pending', async (req, res) => {
    try {
        const payments = await readDB(PAYMENTS_FILE);
        const pending = payments.filter(p => p.status === 'pending');
        res.json(pending);
    } catch (error) {
        res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
});

// Get ALL payments - pending, approved, rejected (Admin only)
app.get('/api/admin/payments/all', async (req, res) => {
    try {
        const payments = await readDB(PAYMENTS_FILE);
        // Sort terbaru dulu
        payments.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        res.json(payments);
    } catch (error) {
        res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
});

// Approve payment (Admin only)
app.post('/api/admin/payments/:id/approve', async (req, res) => {
    try {
        const { id } = req.params;
        
        const payments = await readDB(PAYMENTS_FILE);
        const paymentIndex = payments.findIndex(p => p.id === id);
        
        if (paymentIndex === -1) {
            return res.status(404).json({ error: 'Pembayaran tidak ditemukan' });
        }
        
        const payment = payments[paymentIndex];
        if (payment.status !== 'pending') {
            return res.status(400).json({ error: 'Pembayaran sudah diproses' });
        }
        
        // Update payment status
        payment.status = 'approved';
        payment.approvedAt = new Date().toISOString();
        payments[paymentIndex] = payment;
        await writeDB(PAYMENTS_FILE, payments);
        
        // Add points to user
        const users = await readDB(USERS_FILE);
        const userIndex = users.findIndex(u => u.id === payment.userId);
        if (userIndex !== -1) {
            users[userIndex].points += payment.points;
            await writeDB(USERS_FILE, users);
        }
        
        // Send email to user
        await sendEmailToUser(payment.userEmail, 'approved', payment);
        
        res.json({ 
            message: 'Pembayaran berhasil diapprove',
            payment
        });
    } catch (error) {
        res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
});

// Reject payment (Admin only)
app.post('/api/admin/payments/:id/reject', async (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;
        
        const payments = await readDB(PAYMENTS_FILE);
        const paymentIndex = payments.findIndex(p => p.id === id);
        
        if (paymentIndex === -1) {
            return res.status(404).json({ error: 'Pembayaran tidak ditemukan' });
        }
        
        const payment = payments[paymentIndex];
        payment.status = 'rejected';
        payment.rejectedAt = new Date().toISOString();
        payment.rejectReason = reason;
        payments[paymentIndex] = payment;
        await writeDB(PAYMENTS_FILE, payments);
        
        // Send email to user
        await sendEmailToUser(payment.userEmail, 'rejected', payment);
        
        res.json({ 
            message: 'Pembayaran ditolak',
            payment
        });
    } catch (error) {
        res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
});

// ============================================================================
// EMAIL FUNCTIONS
// ============================================================================

async function sendEmailToAdmin(type, data) {
    try {
        let subject, html;
        
        if (type === 'register') {
            subject = '[BARU] Registrasi User Baru - PolyglotQuest';
            const waNumber = data.phone ? data.phone.replace(/[\s\-\+]/g,'') : '';
            const waLink = waNumber ? `https://wa.me/${waNumber}` : null;
            html = `
                <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.1);">
                  <div style="background:linear-gradient(135deg,#cc1100,#ff6600);padding:24px;text-align:center;">
                    <h2 style="color:#fff;margin:0;font-size:20px;">🎉 User Baru Terdaftar!</h2>
                  </div>
                  <div style="padding:24px;">
                    <table style="width:100%;border-collapse:collapse;">
                      <tr><td style="padding:8px 0;color:#666;width:120px;">👤 Nama</td><td style="padding:8px 0;font-weight:bold;color:#111;">${data.name}</td></tr>
                      <tr><td style="padding:8px 0;color:#666;">📧 Email</td><td style="padding:8px 0;color:#111;"><a href="mailto:${data.email}" style="color:#cc1100;">${data.email}</a></td></tr>
                      <tr><td style="padding:8px 0;color:#666;">📱 No. Ponsel</td><td style="padding:8px 0;color:#111;font-weight:bold;">${data.phone || '-'}</td></tr>
                      <tr><td style="padding:8px 0;color:#666;">🕐 Waktu</td><td style="padding:8px 0;color:#111;">${new Date(data.timestamp).toLocaleString('id-ID')}</td></tr>
                    </table>
                    ${waLink ? `
                    <div style="margin-top:20px;text-align:center;">
                      <a href="${waLink}" style="display:inline-block;background:#25D366;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:15px;">💬 Chat di WhatsApp</a>
                    </div>` : ''}
                    <p style="margin-top:20px;font-size:12px;color:#999;text-align:center;">PolyglotQuest — Platform Pembelajaran 7 Bahasa</p>
                  </div>
                </div>
            `;
        } else if (type === 'payment') {
            subject = '[PAYMENT] Pembayaran Baru Menunggu Verifikasi';
            html = `
                <h2>Pembayaran Baru</h2>
                <p><strong>User:</strong> ${data.userName} (${data.userEmail})</p>
                <p><strong>Paket:</strong> ${data.packageId} - ${data.points} poin</p>
                <p><strong>Nominal:</strong> Rp ${data.amount.toLocaleString('id-ID')}</p>
                <p><strong>Metode:</strong> ${data.method}</p>
                <p><strong>Waktu:</strong> ${new Date(data.createdAt).toLocaleString('id-ID')}</p>
                <p><strong>Bukti Transfer:</strong> <a href="http://localhost:3001${data.proofImage}">Lihat Bukti</a></p>
                <br>
                <p><a href="http://localhost:3001/admin.html">Buka Admin Panel</a></p>
            `;
        }
        
        await transporter.sendMail({
            from: '"PolyglotQuest" <noreply@polyglotquest.com>',
            to: 'nirhvend0403@gmail.com',
            subject,
            html
        });
        
        console.log(`✓ Email sent to admin: ${type}`);
    } catch (error) {
        console.error('Email error:', error);
    }
}

async function sendEmailToUser(email, type, data) {
    try {
        let subject, html;
        
        if (type === 'approved') {
            subject = '✅ Pembayaran Disetujui - PolyglotQuest';
            html = `
                <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                    <h2 style="color:#10b981;">🎉 Pembayaran Berhasil Disetujui!</h2>
                    <p>Halo,</p>
                    <p>Selamat! Pembayaran Anda telah diverifikasi dan disetujui oleh admin.</p>
                    
                    <div style="background:#d1fae5;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid #10b981;">
                        <h3 style="margin-top:0;color:#065f46;">Detail Transaksi:</h3>
                        <p><strong>Paket:</strong> ${data.packageName || 'Package'}</p>
                        <p><strong>Points Ditambahkan:</strong> <span style="color:#10b981;font-size:24px;font-weight:bold;">+${data.points} 💎</span></p>
                        <p><strong>Total Pembayaran:</strong> Rp ${data.amount.toLocaleString('id-ID')}</p>
                        <p><strong>Metode:</strong> ${data.method}</p>
                        <p><strong>Status:</strong> <span style="color:#10b981;font-weight:bold;">Approved ✓</span></p>
                    </div>
                    
                    <p><strong>Points sudah masuk ke akun Anda dan siap digunakan!</strong></p>
                    <p>Anda sekarang dapat membuka bahasa baru atau level premium dengan points yang sudah ditambahkan.</p>
                    
                    <p style="text-align:center;margin:30px 0;">
                        <a href="http://localhost:3001/game.html" 
                           style="background:linear-gradient(135deg,#6366f1,#8b5cf6);color:white;
                                  padding:14px 32px;text-decoration:none;border-radius:12px;
                                  display:inline-block;font-weight:bold;">
                            🚀 Mulai Belajar Sekarang
                        </a>
                    </p>
                    
                    <p style="margin-top:30px;color:#6b7280;font-size:14px;">
                        Terima kasih telah menggunakan PolyglotQuest!<br>
                        Happy Learning! 🌍
                    </p>
                </div>
            `;
        } else if (type === 'rejected') {
            subject = '❌ Pembayaran Ditolak - PolyglotQuest';
            html = `
                <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                    <h2 style="color:#ef4444;">❌ Pembayaran Ditolak</h2>
                    <p>Halo,</p>
                    <p>Mohon maaf, pembayaran Anda tidak dapat diverifikasi.</p>
                    
                    <div style="background:#fee2e2;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid #ef4444;">
                        <h3 style="margin-top:0;color:#991b1b;">Detail Transaksi:</h3>
                        <p><strong>Paket:</strong> ${data.packageName || 'Package'}</p>
                        <p><strong>Total:</strong> Rp ${data.amount.toLocaleString('id-ID')}</p>
                        <p><strong>Alasan Penolakan:</strong> ${data.rejectReason || 'Bukti transfer tidak valid atau tidak sesuai'}</p>
                    </div>
                    
                    <div style="background:#fef3c7;border-left:4px solid #f59e0b;padding:12px;margin:20px 0;">
                        <p style="margin:0;"><strong>💡 Saran:</strong></p>
                        <ul style="margin:8px 0 0 0;padding-left:20px;">
                            <li>Pastikan nominal transfer sesuai dengan harga paket</li>
                            <li>Upload bukti transfer yang jelas dan lengkap</li>
                            <li>Transfer dari rekening atas nama Anda sendiri</li>
                        </ul>
                    </div>
                    
                    <p>Silakan coba lagi dengan bukti transfer yang valid, atau hubungi support untuk bantuan.</p>
                    
                    <p style="text-align:center;margin:30px 0;">
                        <a href="http://localhost:3001/game.html" 
                           style="background:#6366f1;color:white;padding:14px 32px;
                                  text-decoration:none;border-radius:12px;display:inline-block;font-weight:bold;">
                            Coba Lagi
                        </a>
                    </p>
                </div>
            `;
        }
        
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject,
            html
        });
        
        console.log(`✓ Email sent to user: ${email}`);
    } catch (error) {
        console.error('Email error:', error);
    }
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Token tidak tersedia' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Token tidak valid' });
        }
        req.userId = decoded.userId;
        req.userEmail = decoded.email;
        next();
    });
}

// ============================================================================
// START SERVER
// ============================================================================

initDB().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`
╔════════════════════════════════════════╗
║     PolyglotQuest Backend API          ║
║     Server berjalan di port ${PORT}       ║
╚════════════════════════════════════════╝

API Endpoints:
- POST   /api/auth/register
- POST   /api/auth/login
- GET    /api/auth/me
- GET    /api/progress
- POST   /api/progress
- POST   /api/payments
- GET    /api/payments/user
- GET    /api/admin/payments/pending
- GET    /api/admin/payments/all
- POST   /api/admin/payments/:id/approve
- POST   /api/admin/payments/:id/reject

Admin Panel: http://localhost:${PORT}/admin.html
        `);
    });
});

// ============================================================================
// PACKAGE.JSON
// ============================================================================

/*
{
  "name": "polyglotquest-backend",
  "version": "1.0.0",
  "description": "Backend API for PolyglotQuest",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "nodemailer": "^6.9.7",
    "multer": "^1.4.5-lts.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.2"
  }
}
*/

// ============================================================================
// .ENV FILE
// ============================================================================

/*
PORT=3001
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
EMAIL_USER=your-gmail@gmail.com
EMAIL_PASS=your-gmail-app-password
*/
