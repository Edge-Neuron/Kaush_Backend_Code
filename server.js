// Enhanced server.js with better email debugging and error handling
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;

// Enhanced email configuration for Brevo
const emailConfig = {
  host: 'smtp-relay.brevo.com',
  port: 587,
  secure: false, // Use STARTTLS
  auth: {
    user: process.env.EMAIL_USER, // Your Brevo email
    pass: process.env.EMAIL_PASS  // Your Brevo SMTP key
  },
  tls: {
    ciphers: 'SSLv3',
    rejectUnauthorized: false
  }
};

// Debug email configuration
console.log('Email configuration check:');
console.log('EMAIL_USER:', process.env.EMAIL_USER ? '✓ Set' : '✗ Missing');
console.log('EMAIL_PASS:', process.env.EMAIL_PASS ? '✓ Set' : '✗ Missing');
console.log('BASE_URL:', process.env.BASE_URL || 'Not set - using default');

// Create transporter with enhanced error handling
const transporter = nodemailer.createTransport(emailConfig);

// Verify email connection on startup
transporter.verify(function(error, success) {
  if (error) {
    console.error('❌ Email configuration error:', error);
    console.log('Email sending will be disabled');
  } else {
    console.log('✅ Email server is ready to take our messages');
  }
});

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Simple rate limiting (keeping your existing implementation)
const requests = new Map();
app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const maxRequests = 100;
  
  if (!requests.has(ip)) {
    requests.set(ip, []);
  }
  
  const userRequests = requests.get(ip);
  const recentRequests = userRequests.filter(time => now - time < windowMs);
  
  if (recentRequests.length >= maxRequests) {
    return res.status(429).json({ success: false, message: 'Too many requests' });
  }
  
  recentRequests.push(now);
  requests.set(ip, recentRequests);
  next();
});

// Connect to MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// User Schema (keeping your existing schema)
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    minlength: 3,
    maxlength: 30
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  },
  password: { 
    type: String, 
    required: true,
    minlength: 8
  },
  profileData: {
    firstName: String,
    lastName: String,
    preferences: {
      theme: { type: String, default: 'light' },
      notifications: { type: Boolean, default: true },
      audioSettings: {
        sampleRate: { type: Number, default: 44100 },
        bufferSize: { type: Number, default: 512 }
      }
    }
  },
  isVerified: { 
    type: Boolean, 
    default: false 
  },
  verificationToken: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  lastLogin: Date,
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

const User = mongoose.model('User', userSchema);

// Enhanced email sending function
const sendVerificationEmail = async (email, verificationToken, username) => {
  try {
    const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
    const verificationUrl = `${baseUrl}/api/auth/verify/${verificationToken}`;
    
    console.log(`📧 Attempting to send verification email to: ${email}`);
    console.log(`🔗 Verification URL: ${verificationUrl}`);
    
    const mailOptions = {
      from: {
        name: 'JUCE App',
        address: process.env.EMAIL_USER
      },
      to: email,
      subject: 'Verify your JUCE App account',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #333; text-align: center;">Welcome to JUCE App, ${username}!</h2>
          <p>Thank you for registering with JUCE App. To complete your registration, please verify your email address by clicking the button below:</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationUrl}" 
               style="background-color: #007bff; color: white; padding: 15px 30px; 
                      text-decoration: none; border-radius: 5px; display: inline-block;
                      font-weight: bold;">
              Verify My Account
            </a>
          </div>
          
          <p style="color: #666; font-size: 14px; border-top: 1px solid #eee; padding-top: 20px;">
            <strong>If the button doesn't work, copy and paste this link into your browser:</strong><br>
            <a href="${verificationUrl}" style="color: #007bff; word-break: break-all;">${verificationUrl}</a>
          </p>
          
          <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 20px;">
            <p style="color: #666; font-size: 12px; margin: 0;">
              <strong>Security Note:</strong> If you didn't create this account, please ignore this email. 
              This verification link will expire in 24 hours for your security.
            </p>
          </div>
          
          <p style="color: #999; font-size: 11px; text-align: center; margin-top: 30px;">
            This email was sent by JUCE App. Please do not reply to this email.
          </p>
        </div>
      `,
      text: `Welcome to JUCE App, ${username}! Please verify your account by visiting: ${verificationUrl}`
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('✅ Verification email sent successfully:', info.messageId);
    console.log('📬 Brevo response:', info.response);
    return { success: true, messageId: info.messageId };
    
  } catch (error) {
    console.error('❌ Failed to send verification email:', error);
    console.error('Error details:', {
      code: error.code,
      command: error.command,
      response: error.response,
      responseCode: error.responseCode
    });
    return { success: false, error: error.message };
  }
};

// Test email endpoint (for debugging)
app.post('/api/test-email', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    console.log(`🧪 Testing email sending to: ${email}`);
    
    const testResult = await sendVerificationEmail(email, 'test-token-123', 'TestUser');
    
    if (testResult.success) {
      res.json({ 
        success: true, 
        message: 'Test email sent successfully',
        messageId: testResult.messageId
      });
    } else {
      res.status(500).json({ 
        success: false, 
        message: 'Failed to send test email',
        error: testResult.error
      });
    }
  } catch (error) {
    console.error('Test email error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Enhanced User Registration with better email handling
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation (keeping your existing validation)
    if (!username || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username, email, and password are required' 
      });
    }

    if (password.length < 8) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 8 characters long' 
      });
    }

    if (username.length < 3 || username.length > 30) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username must be between 3 and 30 characters' 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: 'User with this email or username already exists' 
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // Create new user
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      verificationToken
    });

    await newUser.save();
    console.log(`✅ User created successfully: ${username} (${email})`);

    // Send verification email
    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      console.log('📧 Email credentials found, attempting to send verification email...');
      
      const emailResult = await sendVerificationEmail(email, verificationToken, username);
      
      if (emailResult.success) {
        console.log('✅ Verification email sent successfully');
        res.status(201).json({ 
          success: true, 
          message: 'Account created successfully! Please check your email for verification.',
          emailSent: true
        });
      } else {
        console.log('⚠️  User created but email failed to send');
        res.status(201).json({ 
          success: true, 
          message: 'Account created successfully, but we couldn\'t send the verification email. Please contact support.',
          emailSent: false,
          emailError: emailResult.error
        });
      }
    } else {
      console.log('⚠️  Email credentials not configured');
      res.status(201).json({ 
        success: true, 
        message: 'Account created successfully. Email verification is currently unavailable.',
        emailSent: false
      });
    }

  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// Health check with email status
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Server is running', 
    timestamp: new Date().toISOString(),
    email: {
      configured: !!(process.env.EMAIL_USER && process.env.EMAIL_PASS),
      host: emailConfig.host,
      port: emailConfig.port
    }
  });
});

// Keep your existing routes (login, forgot password, etc.)
// ... (include all your other existing routes here)

// Start server
const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🏥 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🧪 Test email: POST http://localhost:${PORT}/api/test-email`);
});

module.exports = app;
