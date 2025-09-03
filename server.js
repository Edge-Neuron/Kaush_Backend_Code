// server.js - JUCE Backend with Resend API
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
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
const MONGODB_URI = process.env.MONGODB_URI;
const resend = new Resend(process.env.RESEND_API_KEY);

// --- Middleware ---
app.use(cors());
app.use(express.json());

// --- Connect MongoDB ---
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// --- User schema ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, minlength: 3 },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, minlength: 8 },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);

// --- JWT helper ---
const generateToken = (userId) =>
  jwt.sign({ userId }, JWT_SECRET, { expiresIn: "7d" });

const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token)
    return res.status(401).json({ success: false, message: "Token required" });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err)
      return res.status(403).json({ success: false, message: "Invalid token" });
    req.user = user;
    next();
  });
};

// --- Email functions ---
const sendVerificationEmail = async (email, token) => {
  const url = `${process.env.BASE_URL}/api/auth/verify/${token}`;
  console.log("📨 [DEBUG] Sending verification email via Resend to:", email);

  try {
    const result = await resend.emails.send({
      from: "onboarding@resend.dev", // ✅ replace with a verified sender in Resend
      to: email,
      subject: "Verify your JUCE App account",
      html: `<p>Welcome to Kalpruh! Please verify your email by clicking <a href="${url}">here</a>.</p>`,
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
  });
});

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res
        .status(400)
        .json({ success: false, message: "Missing fields" });

    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing)
      return res
        .status(400)
        .json({ success: false, message: "User already exists" });

    const hashed = await bcrypt.hash(password, 12);
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const user = new User({
      username,
      email,
      password: hashed,
      verificationToken,
    });
    await user.save();

    res.json({ success: true, userId: user._id });

    // Send verification email in background
    sendVerificationEmail(email, verificationToken).then((result) =>
      console.log("📧 [RESULT] Verification email:", result)
    );
  } catch (err) {
    console.error("❌ Register error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Verify email
app.get("/api/auth/verify/:token", async (req, res) => {
  try {
    const user = await User.findOne({ verificationToken: req.params.token });
    if (!user) return res.status(400).send("<h2>Invalid or expired token</h2>");

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    res.send("<h2>Email verified successfully! You can now log in.</h2>");
  } catch (err) {
    res.status(500).send("<h2>Server error</h2>");
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({
      $or: [{ username }, { email: username }],
    });
    if (!user)
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });

    user.lastLogin = new Date();
    await user.save();

    const token = generateToken(user._id);
    res.json({ success: true, token, isVerified: user.isVerified });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Protected test route
app.get("/api/protected", authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: "You accessed a protected route",
    user: req.user,
  });
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
