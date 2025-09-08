// server.js - Enhanced JUCE Backend with Resend API
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import cors from "cors";
import crypto from "crypto";
import dotenv from "dotenv";
import { Resend } from "resend";

dotenv.config();

const app = express();

// Environment variables
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
const MONGODB_URI = process.env.MONGODB_URI;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://yourdomain.com';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Initialize Resend
const resend = new Resend(process.env.RESEND_API_KEY);

// Middleware
app.use(cors({
    origin: [FRONTEND_URL, 'https://embedded.yourdomain.com', 'https://health.yourdomain.com', 'https://agro.yourdomain.com'],
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.set('trust proxy', true)

// Rate limiting implementation (simple in-memory version)
const rateLimitStore = new Map();

const createRateLimit = (maxRequests, windowMs, name = 'unknown') => {
    return (req, res, next) => {
        // Better IP detection with fallbacks
        const getClientIP = (req) => {
            return req.ip || 
                   req.connection?.remoteAddress || 
                   req.socket?.remoteAddress || 
                   (req.connection?.socket ? req.connection.socket.remoteAddress : null) ||
                   req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                   req.headers['x-real-ip'] ||
                   'unknown';
        };

        const clientIP = getClientIP(req);
        const key = `${name}-${clientIP}`;
        const now = Date.now();
        
        // DEBUG LOGGING - Remove these console.logs after debugging
        console.log(`🔍 [RATE LIMIT DEBUG] ${name}:`);
        console.log(`   - IP: ${clientIP}`);
        console.log(`   - Key: ${key}`);
        console.log(`   - URL: ${req.method} ${req.originalUrl}`);
        console.log(`   - Headers:`, {
            'x-forwarded-for': req.headers['x-forwarded-for'],
            'x-real-ip': req.headers['x-real-ip'],
            'user-agent': req.headers['user-agent']
        });
        
        if (!rateLimitStore.has(key)) {
            rateLimitStore.set(key, { count: 1, resetTime: now + windowMs });
            console.log(`   - New entry created, count: 1`);
            return next();
        }
        
        const record = rateLimitStore.get(key);
        console.log(`   - Existing record:`, record);
        console.log(`   - Time remaining: ${Math.max(0, record.resetTime - now)}ms`);
        
        if (now > record.resetTime) {
            record.count = 1;
            record.resetTime = now + windowMs;
            console.log(`   - Window expired, reset count to 1`);
            return next();
        }
        
        if (record.count >= maxRequests) {
            console.log(`   - ❌ RATE LIMIT EXCEEDED: ${record.count}/${maxRequests}`);
            return res.status(429).json({ 
                error: 'Too many requests, please try again later',
                details: {
                    limit: maxRequests,
                    current: record.count,
                    resetTime: new Date(record.resetTime).toISOString(),
                    ip: clientIP
                }
            });
        }
        
        record.count++;
        console.log(`   - ✅ Request allowed, new count: ${record.count}/${maxRequests}`);
        next();
    };
};

const authLimiter = createRateLimit(5, 15 * 60 * 1000,"auth"); // 5 attempts per 15 minutes
const generalLimiter = createRateLimit(100, 15 * 60 * 1000,"general"); // 100 requests per 15 minutes

// Apply rate limiting - but let's be more selective
// Only apply to the problematic routes for now
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);

// Apply general rate limiting to other API routes
app.use('/api/user', generalLimiter);
app.use('/api/audio', generalLimiter);
app.use('/api/feedback', generalLimiter);
app.use('/api/analytics', generalLimiter);

// Add a debug endpoint to check rate limit status
app.get('/api/debug/rate-limit', (req, res) => {
    const getClientIP = (req) => {
        return req.ip || 
               req.connection?.remoteAddress || 
               req.socket?.remoteAddress || 
               (req.connection?.socket ? req.connection.socket.remoteAddress : null) ||
               req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
               req.headers['x-real-ip'] ||
               'unknown';
    };

    const clientIP = getClientIP(req);
    const authKey = `auth-${clientIP}`;
    const generalKey = `general-${clientIP}`;
    
    res.json({
        ip: clientIP,
        rateLimits: {
            auth: rateLimitStore.get(authKey) || 'No record',
            general: rateLimitStore.get(generalKey) || 'No record'
        },
        headers: req.headers,
        allKeys: Array.from(rateLimitStore.keys())
    });
});

// Connect to MongoDB
mongoose
    .connect(MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch((err) => {
        console.error('❌ MongoDB connection error:', err);
        process.exit(1);
    });

// Enhanced User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, sparse: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    profile: {
        firstName: { type: String, required: true },
        lastName: { type: String, required: true },
        avatar: String,
        phoneNumber: String,
        dateOfBirth: Date,
        company: String,
        role: String
    },
    authentication: {
        isEmailVerified: { type: Boolean, default: false },
        emailVerificationToken: String,
        emailVerificationExpires: Date,
        passwordResetToken: String,
        passwordResetExpires: Date,
        lastLogin: Date,
        loginHistory: [{
            timestamp: { type: Date, default: Date.now },
            ipAddress: String,
            userAgent: String,
            location: String
        }]
    },
    subscription: {
        plan: { type: String, default: 'free' },
        startDate: Date,
        endDate: Date,
        features: [String]
    },
    preferences: {
        notifications: { type: Boolean, default: true },
        theme: { type: String, default: 'light' },
        language: { type: String, default: 'en' },
        timezone: String
    },
    applicationData: {
        domain: { type: String, enum: ['embedded', 'health', 'agro'], required: true },
        deviceId: String,
        installationDate: { type: Date, default: Date.now }
    }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Audio Session Schema
const audioSessionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    sessionId: { type: String, required: true, unique: true },
    deviceInfo: {
        deviceId: String,
        deviceModel: String,
        osVersion: String,
        appVersion: String,
        hardwareSpecs: {
            microphoneModel: String,
            samplingRate: Number,
            bitDepth: Number
        }
    },
    timestamp: { type: Date, default: Date.now },
    duration: Number, // in seconds
    audioMetrics: {
        averageDecibel: Number,
        peakDecibel: Number,
        frequencyAnalysis: mongoose.Schema.Types.Mixed,
        noiseFloor: Number,
        signalToNoiseRatio: Number
    },
    environmentalData: {
        location: String,
        ambientTemperature: Number,
        humidity: Number,
        recordingEnvironment: { type: String, enum: ['indoor', 'outdoor', 'studio'] }
    },
    userSettings: {
        gainLevel: Number,
        filterSettings: mongoose.Schema.Types.Mixed,
        processingMode: String
    }
});

const AudioSession = mongoose.model('AudioSession', audioSessionSchema);

// Feedback Schema
const feedbackSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    feedbackType: { type: String, enum: ['bug', 'feature', 'general', 'rating'], required: true },
    category: { type: String, enum: ['audio', 'ui', 'performance', 'documentation'], required: true },
    severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' },
    title: { type: String, required: true },
    description: { type: String, required: true },
    rating: { type: Number, min: 1, max: 5 },
    metadata: {
        appVersion: String,
        deviceInfo: mongoose.Schema.Types.Mixed,
        sessionLogs: String,
        screenshots: [String],
        audioSamples: [String]
    },
    status: { type: String, enum: ['open', 'in_progress', 'resolved', 'closed'], default: 'open' },
    adminResponse: String,
    resolvedAt: Date
}, { timestamps: true });

const Feedback = mongoose.model('Feedback', feedbackSchema);

// Analytics Schema
const analyticsSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    event: { type: String, required: true },
    properties: mongoose.Schema.Types.Mixed,
    sessionId: String,
    timestamp: { type: Date, default: Date.now }
});

const Analytics = mongoose.model('Analytics', analyticsSchema);

// JWT Helper Functions
const generateToken = (userId) =>
    jwt.sign({ userId }, JWT_SECRET, { expiresIn: "7d" });

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Email Templates and Functions
const emailTemplates = {
    emailVerification: (name, token) => ({
        subject: 'Verify Your Email - JUCE App',
        html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
                <h1 style="color: white; margin: 0;">Welcome to JUCE App!</h1>
            </div>
            <div style="padding: 30px; background: #f8f9fa;">
                <h2>Hi ${name}!</h2>
                <p>Thanks for joining JUCE App. To get started, please verify your email address by clicking the button below:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${BASE_URL}/api/auth/verify/${token}" 
                       style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        Verify Email Address
                    </a>
                </div>
                <p>If the button doesn't work, copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #666;">${BASE_URL}/api/auth/verify/${token}</p>
                <p>This verification link will expire in 24 hours.</p>
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
                <p style="color: #666; font-size: 12px;">If you didn't create this account, please ignore this email.</p>
            </div>
        </div>`
    }),
    
    passwordReset: (name, token) => ({
        subject: 'Reset Your Password - JUCE App',
        html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #dc3545; padding: 20px; text-align: center;">
                <h1 style="color: white; margin: 0;">Password Reset Request</h1>
            </div>
            <div style="padding: 30px; background: #f8f9fa;">
                <h2>Hi ${name}!</h2>
                <p>We received a request to reset your password. Click the button below to reset it:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${BASE_URL}/api/auth/reset-password/${token}" 
                       style="background: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        Reset Password
                    </a>
                </div>
                <p>This password reset link will expire in 1 hour.</p>
                <p>If you didn't request this password reset, please ignore this email.</p>
            </div>
        </div>`
    }),

    welcome: (name) => ({
        subject: 'Welcome to JUCE App - Get Started!',
        html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); padding: 20px; text-align: center;">
                <h1 style="color: white; margin: 0;">Welcome to JUCE App!</h1>
            </div>
            <div style="padding: 30px; background: #f8f9fa;">
                <h2>Hi ${name}!</h2>
                <p>Your email has been verified successfully! You're now ready to explore all the features JUCE App has to offer.</p>
                <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <h3>Getting Started:</h3>
                    <ul>
                        <li>Configure your audio settings</li>
                        <li>Set up your preferences</li>
                        <li>Start your first audio session</li>
                        <li>Explore advanced features</li>
                    </ul>
                </div>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${FRONTEND_URL}" 
                       style="background: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        Launch JUCE App
                    </a>
                </div>
                <p>Need help? Contact our support team anytime!</p>
            </div>
        </div>`
    })
};

// Email service functions using Resend
const sendEmail = async (to, template) => {
    try {
        console.log(`📨 [DEBUG] Sending ${template.subject} email via Resend to:`, to);
        
        const result = await resend.emails.send({
            from: "noreply@onboarding-kaush.kalpruh.com",
            to: to,
            subject: template.subject,
            html: template.html,
        });
        
        console.log("✅ [EMAIL SUCCESS]", result);
        return { success: true, method: "Resend", id: result.id };
    } catch (err) {
        console.error("❌ [EMAIL ERROR]", err.message);
        return { success: false, error: err.message, method: "Resend" };
    }
};

// --- Routes ---

// Health check
app.get("/api/health", (req, res) => {
    res.json({
        status: "ok",
        db: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
        timestamp: new Date().toISOString()
    });
});

// Enhanced Registration
app.post("/api/auth/register", async (req, res) => {
    try {
        const { username, email, password, firstName, lastName, domain = 'embedded' } = req.body;
        
        // Validation
        if (!email || !password || !firstName || !lastName) {
            return res.status(400).json({ 
                success: false, 
                message: "Email, password, firstName, and lastName are required" 
            });
        }

        if (password.length < 8) {
            return res.status(400).json({ 
                success: false, 
                message: "Password must be at least 8 characters long" 
            });
        }

        // Check if user exists
        const existingUser = await User.findOne({ 
            $or: [{ email }, ...(username ? [{ username }] : [])] 
        });
        
        if (existingUser) {
            return res.status(400).json({ 
                success: false, 
                message: existingUser.email === email ? "Email already registered" : "Username already taken"
            });
        }

        // Create user
        const hashedPassword = await bcrypt.hash(password, 12);
        const emailVerificationToken = crypto.randomBytes(32).toString("hex");
        const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        
        const user = new User({
            username,
            email,
            password: hashedPassword,
            profile: {
                firstName,
                lastName
            },
            authentication: {
                emailVerificationToken,
                emailVerificationExpires
            },
            applicationData: {
                domain
            }
        });

        await user.save();

        res.json({ 
            success: true, 
            message: "Registration successful. Please check your email to verify your account.",
            userId: user._id 
        });

        // Send verification email in background
        const template = emailTemplates.emailVerification(firstName, emailVerificationToken);
        sendEmail(email, template).then((result) =>
            console.log("📧 [RESULT] Verification email:", result)
        );

    } catch (err) {
        console.error("❌ Register error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Email verification
app.get("/api/auth/verify/:token", async (req, res) => {
    try {
        const user = await User.findOne({ 
            'authentication.emailVerificationToken': req.params.token,
            'authentication.emailVerificationExpires': { $gt: new Date() }
        });
        
        if (!user) {
            return res.status(400).send(`
                <div style="text-align: center; font-family: Arial, sans-serif; padding: 50px;">
                    <h2 style="color: #dc3545;">❌ Invalid or Expired Token</h2>
                    <p>This verification link is either invalid or has expired.</p>
                    <p>Please request a new verification email.</p>
                </div>
            `);
        }

        user.authentication.isEmailVerified = true;
        user.authentication.emailVerificationToken = undefined;
        user.authentication.emailVerificationExpires = undefined;
        await user.save();

        res.send(`
            <div style="text-align: center; font-family: Arial, sans-serif; padding: 50px;">
                <h2 style="color: #28a745;">✅ Email Verified Successfully!</h2>
                <p>Your email has been verified. You can now log in to your account.</p>
                <a href="${FRONTEND_URL}" style="background: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px;">
                    Go to JUCE App
                </a>
            </div>
        `);

        // Send welcome email
        const template = emailTemplates.welcome(user.profile.firstName);
        sendEmail(user.email, template);

    } catch (err) {
        console.error("❌ Verification error:", err);
        res.status(500).send("<h2>Server error during verification</h2>");
    }
});

// Enhanced Login
app.post("/api/auth/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ 
                success: false, 
                message: "Username and password are required" 
            });
        }

        const user = await User.findOne({
            $or: [{ username }, { email: username }],
        });
        
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: "Invalid credentials" 
            });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (!isValidPassword) {
            return res.status(401).json({ 
                success: false, 
                message: "Invalid credentials" 
            });
        }

        // Update login info
        const loginInfo = {
            timestamp: new Date(),
            ipAddress: req.ip,
            userAgent: req.get('User-Agent') || 'Unknown'
        };

        user.authentication.lastLogin = new Date();
        user.authentication.loginHistory.push(loginInfo);
        
        // Keep only last 10 login records
        if (user.authentication.loginHistory.length > 10) {
            user.authentication.loginHistory = user.authentication.loginHistory.slice(-10);
        }
        
        await user.save();

        const token = generateToken(user._id);
        
        res.json({ 
            success: true, 
            token, 
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                firstName: user.profile.firstName,
                lastName: user.profile.lastName,
                isEmailVerified: user.authentication.isEmailVerified,
                domain: user.applicationData.domain
            }
        });

    } catch (err) {
        console.error("❌ Login error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Password reset request
app.post("/api/auth/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ 
                success: false, 
                message: "Email is required" 
            });
        }

        const user = await User.findOne({ email });
        
        if (!user) {
            // Return success even if user doesn't exist for security
            return res.json({ 
                success: true, 
                message: "If an account with that email exists, a password reset link has been sent." 
            });
        }

        const resetToken = crypto.randomBytes(32).toString("hex");
        const resetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

        user.authentication.passwordResetToken = resetToken;
        user.authentication.passwordResetExpires = resetExpires;
        await user.save();

        // Send password reset email
        const template = emailTemplates.passwordReset(user.profile.firstName, resetToken);
        const emailResult = await sendEmail(user.email, template);
        
        if (emailResult.success) {
            res.json({ 
                success: true, 
                message: "Password reset link has been sent to your email." 
            });
        } else {
            res.status(500).json({ 
                success: false, 
                message: "Failed to send password reset email." 
            });
        }

    } catch (err) {
        console.error("❌ Forgot password error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

//when user clicks on reset link
// Enhanced password reset GET route with debugging
// Replace your password reset GET route with this:
app.get("/api/auth/reset-password/:token", async (req, res) => {
    console.log(`🔍 [RESET GET] Token: ${req.params.token}`);
    console.log(`🔍 [RESET GET] IP: ${req.ip}`);
    
    try {
        const user = await User.findOne({ 
            'authentication.passwordResetToken': req.params.token,
            'authentication.passwordResetExpires': { $gt: new Date() }
        });
        
        if (!user) {
            console.log(`❌ [RESET GET] Invalid/expired token: ${req.params.token}`);
            return res.status(400).send(`
                <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px;">
                    <div style="background: #dc3545; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
                        <h2 style="margin: 0;">❌ Invalid or Expired Link</h2>
                    </div>
                    <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px;">
                        <p>This password reset link is either invalid or has expired.</p>
                        <p>Please <a href="${FRONTEND_URL}/forgot-password" style="color: #007bff;">request a new password reset</a>.</p>
                    </div>
                </div>
            `);
        }

        console.log(`✅ [RESET GET] Valid token, showing form for user: ${user.email}`);
        
        // Return HTML form for password reset
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Reset Your Password - JUCE App</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        margin: 0;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    }
                    .container {
                        background: white;
                        padding: 40px;
                        border-radius: 12px;
                        box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                        width: 100%;
                        max-width: 400px;
                    }
                    .header {
                        text-align: center;
                        margin-bottom: 30px;
                    }
                    .header h1 {
                        color: #333;
                        margin: 0 0 10px 0;
                        font-size: 24px;
                    }
                    .header p {
                        color: #666;
                        margin: 0;
                    }
                    .form-group {
                        margin-bottom: 20px;
                    }
                    label {
                        display: block;
                        margin-bottom: 8px;
                        color: #333;
                        font-weight: 500;
                    }
                    input[type="password"] {
                        width: 100%;
                        padding: 12px;
                        border: 2px solid #e1e5e9;
                        border-radius: 8px;
                        font-size: 16px;
                        box-sizing: border-box;
                        transition: border-color 0.3s;
                    }
                    input[type="password"]:focus {
                        outline: none;
                        border-color: #667eea;
                    }
                    .btn {
                        width: 100%;
                        padding: 12px;
                        background: #667eea;
                        color: white;
                        border: none;
                        border-radius: 8px;
                        font-size: 16px;
                        font-weight: 500;
                        cursor: pointer;
                        transition: background 0.3s;
                    }
                    .btn:hover {
                        background: #5a6fd8;
                    }
                    .btn:disabled {
                        background: #ccc;
                        cursor: not-allowed;
                    }
                    .error {
                        color: #dc3545;
                        margin-top: 10px;
                        display: none;
                    }
                    .success {
                        color: #28a745;
                        margin-top: 10px;
                        display: none;
                    }
                    .password-requirements {
                        font-size: 12px;
                        color: #666;
                        margin-top: 5px;
                    }
                    .loading {
                        display: none;
                        text-align: center;
                        margin-top: 10px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔒 Reset Your Password</h1>
                        <p>Enter your new password below</p>
                    </div>
                    
                    <form id="resetForm">
                        <div class="form-group">
                            <label for="password">New Password</label>
                            <input type="password" id="password" name="password" required minlength="8">
                            <div class="password-requirements">
                                Must be at least 8 characters long
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label for="confirmPassword">Confirm New Password</label>
                            <input type="password" id="confirmPassword" name="confirmPassword" required minlength="8">
                        </div>
                        
                        <button type="submit" class="btn" id="submitBtn">Reset Password</button>
                        
                        <div class="loading" id="loading">
                            Resetting your password...
                        </div>
                        
                        <div class="error" id="error"></div>
                        <div class="success" id="success"></div>
                    </form>
                </div>

                <script>
                    document.getElementById('resetForm').addEventListener('submit', async function(e) {
                        e.preventDefault();
                        
                        const password = document.getElementById('password').value;
                        const confirmPassword = document.getElementById('confirmPassword').value;
                        const errorDiv = document.getElementById('error');
                        const successDiv = document.getElementById('success');
                        const submitBtn = document.getElementById('submitBtn');
                        const loading = document.getElementById('loading');
                        
                        // Clear previous messages
                        errorDiv.style.display = 'none';
                        successDiv.style.display = 'none';
                        
                        // Validation
                        if (password !== confirmPassword) {
                            errorDiv.textContent = 'Passwords do not match';
                            errorDiv.style.display = 'block';
                            return;
                        }
                        
                        if (password.length < 8) {
                            errorDiv.textContent = 'Password must be at least 8 characters long';
                            errorDiv.style.display = 'block';
                            return;
                        }
                        
                        // Submit
                        submitBtn.disabled = true;
                        loading.style.display = 'block';
                        
                        try {
                            const response = await fetch(window.location.href, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json'
                                },
                                body: JSON.stringify({ password })
                            });
                            
                            const result = await response.json();
                            
                            if (result.success) {
                                successDiv.textContent = result.message;
                                successDiv.style.display = 'block';
                                document.getElementById('resetForm').reset();
                                
                                // Redirect after 3 seconds
                                setTimeout(() => {
                                    window.location.href = '${FRONTEND_URL || BASE_URL}';
                                }, 3000);
                            } else {
                                errorDiv.textContent = result.message || 'An error occurred';
                                errorDiv.style.display = 'block';
                            }
                        } catch (error) {
                            errorDiv.textContent = 'Network error. Please try again.';
                            errorDiv.style.display = 'block';
                        } finally {
                            submitBtn.disabled = false;
                            loading.style.display = 'none';
                        }
                    });
                </script>
            </body>
            </html>
        `);

    } catch (err) {
        console.error("❌ [RESET GET] Verification error:", err);
        res.status(500).send(`
            <div style="text-align: center; font-family: Arial, sans-serif; padding: 50px;">
                <h2 style="color: #dc3545;">Server Error</h2>
                <p>Something went wrong. Please try again later.</p>
            </div>
        `);
    }
});

// Password reset
app.post("/api/auth/reset-password/:token", async (req, res) => {
    try {
        const { password } = req.body;
        const { token } = req.params;
        
        if (!password) {
            return res.status(400).json({ 
                success: false, 
                message: "Password is required" 
            });
        }

        if (password.length < 8) {
            return res.status(400).json({ 
                success: false, 
                message: "Password must be at least 8 characters long" 
            });
        }

        const user = await User.findOne({
            'authentication.passwordResetToken': token,
            'authentication.passwordResetExpires': { $gt: new Date() }
        });
        
        if (!user) {
            return res.status(400).json({ 
                success: false, 
                message: "Invalid or expired reset token" 
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        user.password = hashedPassword;
        user.authentication.passwordResetToken = undefined;
        user.authentication.passwordResetExpires = undefined;
        await user.save();

        res.json({ 
            success: true, 
            message: "Password has been reset successfully" 
        });

    } catch (err) {
        console.error("❌ Reset password error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Get user profile
app.get("/api/user/profile", authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: "User not found" 
            });
        }

        res.json({ 
            success: true, 
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                profile: user.profile,
                preferences: user.preferences,
                subscription: user.subscription,
                isEmailVerified: user.authentication.isEmailVerified,
                lastLogin: user.authentication.lastLogin,
                createdAt: user.createdAt
            }
        });

    } catch (err) {
        console.error("❌ Profile fetch error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Update user profile
app.put("/api/user/profile", authenticateToken, async (req, res) => {
    try {
        const updates = req.body;
        const allowedUpdates = ['profile', 'preferences'];
        const filteredUpdates = {};
        
        allowedUpdates.forEach(field => {
            if (updates[field]) {
                filteredUpdates[field] = updates[field];
            }
        });

        const user = await User.findByIdAndUpdate(
            req.user.userId,
            { $set: filteredUpdates },
            { new: true, select: '-password' }
        );

        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: "User not found" 
            });
        }

        res.json({ 
            success: true, 
            message: "Profile updated successfully",
            user 
        });

    } catch (err) {
        console.error("❌ Profile update error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Audio session endpoints
app.post("/api/audio/session", authenticateToken, async (req, res) => {
    try {
        const sessionData = {
            userId: req.user.userId,
            sessionId: crypto.randomUUID(),
            ...req.body
        };

        const session = new AudioSession(sessionData);
        await session.save();

        res.json({ 
            success: true, 
            message: "Audio session recorded",
            sessionId: session.sessionId 
        });

    } catch (err) {
        console.error("❌ Audio session error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/audio/sessions", authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const skip = (page - 1) * limit;

        const sessions = await AudioSession.find({ userId: req.user.userId })
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(parseInt(limit));

        const total = await AudioSession.countDocuments({ userId: req.user.userId });

        res.json({ 
            success: true, 
            sessions,
            pagination: {
                currentPage: parseInt(page),
                totalPages: Math.ceil(total / limit),
                totalSessions: total
            }
        });

    } catch (err) {
        console.error("❌ Fetch sessions error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Feedback endpoints
app.post("/api/feedback", authenticateToken, async (req, res) => {
    try {
        const feedbackData = {
            userId: req.user.userId,
            ...req.body
        };

        const feedback = new Feedback(feedbackData);
        await feedback.save();

        res.json({ 
            success: true, 
            message: "Feedback submitted successfully",
            feedbackId: feedback._id 
        });

    } catch (err) {
        console.error("❌ Feedback error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/feedback", authenticateToken, async (req, res) => {
    try {
        const feedback = await Feedback.find({ userId: req.user.userId })
            .sort({ createdAt: -1 });

        res.json({ success: true, feedback });

    } catch (err) {
        console.error("❌ Fetch feedback error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Analytics endpoint
app.post("/api/analytics/event", authenticateToken, async (req, res) => {
    try {
        const eventData = {
            userId: req.user.userId,
            ...req.body
        };

        const analyticsEvent = new Analytics(eventData);
        await analyticsEvent.save();

        res.json({ success: true, message: "Event logged" });

    } catch (err) {
        console.error("❌ Analytics error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Protected test route
app.get("/api/protected", authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('username email profile');
        res.json({
            success: true,
            message: "You accessed a protected route",
            user
        });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📧 Email service: Resend`);
    console.log(`🌐 Frontend URL: ${FRONTEND_URL}`);
});
