// server.js - JUCE Backend with Mailgun API Integration
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');
const formData = require('form-data');
const Mailgun = require('mailgun.js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const MONGODB_URI = process.env.MONGODB_URI;

// Middleware
app.use(cors());
app.use(express.json());

// Connect MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, minlength: 3, maxlength: 30 },
  email: { type: String, required: true, unique: true, match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
  password: { type: String, required: true, minlength: 8 },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Mailgun Config (API only)
const mailgun = new Mailgun(formData);
const mg = mailgun.client({
  username: 'api',
  key: process.env.MAILGUN_API_KEY
});

// --- Helper functions ---
const generateToken = (userId) =>
  jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid token' });
    req.user = user;
    next();
  });
};

const sendVerificationEmail = async (email, verificationToken) => {
  const url = `${process.env.BASE_URL}/api/auth/verify/${verificationToken}`;
  try {
    console.log("📨 [DEBUG] Sending verification email via Mailgun API to:", email);

    const body = await mg.messages.create(process.env.MAILGUN_DOMAIN, {
      from: `JUCE App <mailgun@${process.env.MAILGUN_DOMAIN}>`,
      to: [email],
      subject: 'Verify your JUCE App account',
      text: `Please verify your account by visiting ${url}`,
      html: `<p>Please verify your account by clicking <a href="${url}">here</a></p>`
    });

    console.log("✅ [API SUCCESS] Mailgun API response:", body);
    return { success: true, method: 'API', id: body.id };
  } catch (e) {
    console.error("❌ [API ERROR]:", e.message);
    return { success: false, error: e.message, method: 'API' };
  }
};

const sendPasswordResetEmail = async (email, token) => {
  const resetUrl = `${process.env.BASE_URL}/api/auth/reset-password/${token}`;
  try {
    console.log("📨 [DEBUG] Sending password reset email via Mailgun API to:", email);

    const body = await mg.messages.create(process.env.MAILGUN_DOMAIN, {
      from: `JUCE App <mailgun@${process.env.MAILGUN_DOMAIN}>`,
      to: [email],
      subject: 'Reset your JUCE App password',
      text: `Reset your password here: ${resetUrl}`,
      html: `<p>Click <a href="${resetUrl}">here</a> to reset your password.</p>`
    });

    console.log("✅ [API SUCCESS] Password reset email sent:", body);
    return { success: true, method: 'API', id: body.id };
  } catch (e) {
    console.error("❌ [API ERROR]:", e.message);
    return { success: false, error: e.message, method: 'API' };
  }
};

// --- Routes ---
app.get('/', (req, res) => {
  res.json({ message: 'JUCE Backend API with Mailgun running' });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ success: false, message: 'Missing fields' });

    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) return res.status(400).json({ success: false, message: 'User exists' });

    const hashed = await bcrypt.hash(password, 12);
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const user = new User({ username, email, password: hashed, verificationToken });
    await user.save();

    // ✅ Respond immediately
    res.json({ success: true, userId: user._id });

    // 🔄 Send email in background
    console.log("📧 [DEBUG] Preparing to send verification email...");
    sendVerificationEmail(email, verificationToken)
      .then(result => console.log("📧 [RESULT] Verification email:", result))
      .catch(err => console.error("❌ [ERROR] Verification email failed:", err));
  } catch (err) {
    console.error("❌ Register error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ $or: [{ username }, { email: username }] });
    if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    user.lastLogin = new Date();
    await user.save();

    const token = generateToken(user._id);
    res.json({ success: true, token, isVerified: user.isVerified });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Verify email
app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const user = await User.findOne({ verificationToken: req.params.token });
    if (!user) return res.status(400).send('<h2>Invalid or expired token</h2>');

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    res.send('<h2>Email verified successfully! You can now log in.</h2>');
  } catch (err) {
    res.status(500).send('<h2>Server error</h2>');
  }
});

// Forgot password
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const token = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hr
    await user.save();

    await sendPasswordResetEmail(email, token);
    res.json({ success: true, message: 'Password reset email sent' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Reset password
app.post('/api/auth/reset-password/:token', async (req, res) => {
  try {
    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() }
    });
    if (!user) return res.status(400).json({ success: false, message: 'Invalid/expired token' });

    const hashed = await bcrypt.hash(req.body.password, 12);
    user.password = hashed;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ success: true, message: 'Password reset successful' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Protected test route
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ success: true, message: 'You accessed a protected route', user: req.user });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
