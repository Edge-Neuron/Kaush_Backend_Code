// server.js - JUCE Backend Server with Working Brevo Integration
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
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const MONGODB_URI = process.env.MONGODB_URI;

console.log('🚀 Starting JUCE Backend Server...');
console.log('📦 MongoDB URI configured:', !!MONGODB_URI);

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Rate limiting
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
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// User Schema
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

// Email Configuration for Brevo
const emailConfig = {
  host: 'smtp-relay.brevo.com',
  port: 587,
  secure: false,
  auth: {
    user: '9628b7001@smtp-brevo.com',
    pass: 'BrevoSMTPKey-xsmtpsib-a3b48f04e0b9926ee36f9668131698393f51525bfa5cdf5adc789be3af992601-9L5zPSxDUTZJbhG3'
  },
  tls: {
    ciphers: 'SSLv3',
    rejectUnauthorized: false
  }
};

console.log('📧 Email Configuration:');
console.log('  Host:', emailConfig.host);
console.log('  Port:', emailConfig.port);
console.log('  User:', emailConfig.auth.user);
console.log('  Pass: [CONFIGURED]');

// Create email transporter
const transporter = nodemailer.createTransport(emailConfig);

// Verify email connection on startup
transporter.verify(function(error, success) {
  if (error) {
    console.error('❌ Email server connection failed:', error.message);
  } else {
    console.log('✅ Email server connection successful - Ready to send emails');
  }
});

// Helper Functions
const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Email sending function
const sendVerificationEmail = async (email, verificationToken, username) => {
  try {
    const verificationUrl = `https://kaushbackendcode-production.up.railway.app/api/auth/verify/${verificationToken}`;
    
    console.log(`📧 Sending verification email to: ${email}`);
    console.log(`🔗 Verification URL: ${verificationUrl}`);
    
    const mailOptions = {
      from: {
        name: 'JUCE App',
        address: '9628b7001@smtp-brevo.com'
      },
      to: email,
      subject: 'Verify your JUCE App account',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Verify Your JUCE App Account</title>
        </head>
        <body style="margin: 0; padding: 0; background-color: #f4f4f4; font-family: Arial, sans-serif;">
          <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 40px 20px;">
            <div style="text-align: center; margin-bottom: 40px;">
              <h1 style="color: #333; margin: 0; font-size: 28px;">Welcome to JUCE App!</h1>
              <p style="color: #666; margin: 10px 0 0 0; font-size: 16px;">Hi ${username}, thanks for joining us!</p>
            </div>
            
            <div style="background-color: #f8f9fa; padding: 30px; border-radius: 8px; margin-bottom: 30px;">
              <p style="color: #333; font-size: 16px; line-height: 1.5; margin: 0 0 20px 0;">
                To complete your registration and start using JUCE App, please verify your email address by clicking the button below:
              </p>
              
              <div style="text-align: center; margin: 30px 0;">
                <a href="${verificationUrl}" 
                   style="background-color: #007bff; color: white; padding: 15px 30px; 
                          text-decoration: none; border-radius: 5px; display: inline-block;
                          font-weight: bold; font-size: 16px;">
                  Verify My Account
                </a>
              </div>
            </div>
            
            <div style="border-top: 1px solid #eee; padding-top: 20px;">
              <p style="color: #666; font-size: 14px; line-height: 1.5;">
                <strong>If the button doesn't work, copy and paste this link into your browser:</strong><br>
                <a href="${verificationUrl}" style="color: #007bff; word-break: break-all;">${verificationUrl}</a>
              </p>
            </div>
            
            <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin-top: 30px;">
              <p style="color: #856404; font-size: 12px; margin: 0;">
                <strong>Security Note:</strong> If you didn't create this account, please ignore this email. 
                This verification link will expire in 24 hours.
              </p>
            </div>
            
            <div style="text-align: center; margin-top: 40px; border-top: 1px solid #eee; padding-top: 20px;">
              <p style="color: #999; font-size: 12px; margin: 0;">
                This email was sent by JUCE App<br>
                Please do not reply to this email.
              </p>
            </div>
          </div>
        </body>
        </html>
      `,
      text: `Welcome to JUCE App, ${username}! 
      
Please verify your account by visiting: ${verificationUrl}

If you didn't create this account, please ignore this email.

- JUCE App Team`
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('✅ Email sent successfully!');
    console.log('📬 Message ID:', info.messageId);
    console.log('📤 Response:', info.response);
    
    return { success: true, messageId: info.messageId };
    
  } catch (error) {
    console.error('❌ Failed to send verification email:', error);
    return { success: false, error: error.message };
  }
};

// Routes

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'JUCE Backend API is running!', 
    status: 'success',
    version: '1.0.0',
    baseUrl: 'https://kaushbackendcode-production.up.railway.app',
    endpoints: {
      health: 'GET /api/health',
      register: 'POST /api/auth/register',
      login: 'POST /api/auth/login',
      testEmail: 'POST /api/test-email',
      forgotPassword: 'POST /api/auth/forgot-password',
      resetPassword: 'POST /api/auth/reset-password',
      verifyEmail: 'GET /api/auth/verify/:token',
      profile: 'GET /api/user/profile',
      updateProfile: 'PUT /api/user/profile'
    }
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Server is running', 
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    email: 'configured'
  });
});

// Test email endpoint
app.post('/api/test-email', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    console.log(`🧪 Testing email to: ${email}`);
    
    const result = await sendVerificationEmail(email, 'test-token-' + Date.now(), 'TestUser');
    
    if (result.success) {
      res.json({ 
        success: true, 
        message: 'Test email sent successfully',
        messageId: result.messageId
      });
    } else {
      res.status(500).json({ 
        success: false, 
        message: 'Failed to send test email',
        error: result.error
      });
    }
  } catch (error) {
    console.error('Test email error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// User Registration
app.post('/api/auth/register', async (req, res) => {
  console.log('📝 Registration request received');
  console.log('📋 Request body:', { 
    username: req.body.username, 
    email: req.body.email,
    hasPassword: !!req.body.password 
  });

  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      console.log('❌ Missing required fields');
      return res.status(400).json({ 
        success: false, 
        message: 'Username, email, and password are required' 
      });
    }

    if (password.length < 8) {
      console.log('❌ Password too short');
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 8 characters long' 
      });
    }

    if (username.length < 3 || username.length > 30) {
      console.log('❌ Invalid username length');
      return res.status(400).json({ 
        success: false, 
        message: 'Username must be between 3 and 30 characters' 
      });
    }

    // Check if user already exists
    console.log('🔍 Checking for existing user...');
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      console.log('❌ User already exists');
      return res.status(400).json({ 
        success: false, 
        message: 'User with this email or username already exists' 
      });
    }

    // Hash password
    console.log('🔒 Hashing password...');
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    console.log('🎫 Generated verification token');

    // Create new user
    console.log('👤 Creating new user...');
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      verificationToken,
      profileData: {
        preferences: {
          theme: 'light',
          notifications: true,
          audioSettings: {
            sampleRate: 44100,
            bufferSize: 512
          }
        }
      }
    });

    await newUser.save();
    console.log('✅ User saved to database:', newUser._id);

    // Send verification email
    console.log('📧 Attempting to send verification email...');
    const emailResult = await sendVerificationEmail(email, verificationToken, username);
    
    if (emailResult.success) {
      console.log('✅ Verification email sent successfully');
      res.status(201).json({ 
        success: true, 
        message: 'Account created successfully! Please check your email for verification.',
        userId: newUser._id,
        emailSent: true
      });
    } else {
      console.log('⚠️ User created but email failed');
      res.status(201).json({ 
        success: true, 
        message: 'Account created successfully, but verification email could not be sent. Please contact support.',
        userId: newUser._id,
        emailSent: false,
        emailError: emailResult.error
      });
    }

  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error: ' + error.message 
    });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username and password are required' 
      });
    }

    // Find user by username or email
    const user = await User.findOne({ 
      $or: [{ username }, { email: username }] 
    });

    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    const token = generateToken(user._id);

    res.json({ 
      success: true, 
      message: 'Login successful',
      token,
      username: user.username,
      userId: user._id,
      isVerified: user.isVerified
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// Email Verification
app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    console.log('🔍 Verifying token:', token);

    const user = await User.findOne({ verificationToken: token });
    
    if (!user) {
      console.log('❌ Invalid verification token');
      return res.status(400).send(`
        <html>
          <head><title>Verification Failed</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px; background-color: #f4f4f4;">
            <div style="max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
              <h2 style="color: #dc3545;">❌ Verification Failed</h2>
              <p style="color: #666;">The verification link is invalid or has already been used.</p>
              <p><a href="https://kaushbackendcode-production.up.railway.app" style="color: #007bff;">Return to App</a></p>
            </div>
          </body>
        </html>
      `);
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    console.log('✅ Email verified for user:', user.username);

    res.send(`
      <html>
        <head><title>Email Verified</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px; background-color: #f4f4f4;">
          <div style="max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <h2 style="color: #28a745;">✅ Email Verified Successfully!</h2>
            <p style="color: #666;">Your JUCE App account has been verified. You can now close this window and log in to the application.</p>
            <div style="margin: 30px 0;">
              <a href="https://kaushbackendcode-production.up.railway.app" 
                 style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Return to App
              </a>
            </div>
          </div>
        </body>
      </html>
    `);

  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).send(`
      <html>
        <head><title>Verification Error</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px; background-color: #f4f4f4;">
          <div style="max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px;">
            <h2 style="color: #dc3545;">Verification Failed</h2>
            <p>An error occurred during verification. Please try again or contact support.</p>
          </div>
        </body>
      </html>
    `);
  }
});

// Get User Profile (Protected Route)
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password -resetPasswordToken -verificationToken');
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    res.json({ 
      success: true, 
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profileData: user.profileData,
        isVerified: user.isVerified,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    });

  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// Update User Profile (Protected Route)
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, preferences } = req.body;
    
    const user = await User.findById(req.user.userId);
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // Update profile data
    if (firstName !== undefined) user.profileData.firstName = firstName;
    if (lastName !== undefined) user.profileData.lastName = lastName;
    if (preferences) {
      user.profileData.preferences = { ...user.profileData.preferences, ...preferences };
    }

    await user.save();

    res.json({ 
      success: true, 
      message: 'Profile updated successfully',
      profileData: user.profileData
    });

  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// Logout (Protected Route)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ 
    success: true, 
    message: 'Logged out successfully' 
  });
});

// Forgot Password
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required' 
      });
    }

    const user = await User.findOne({ email });
    
    if (!user) {
      return res.json({ 
        success: true, 
        message: 'If an account with that email exists, a reset link has been sent.' 
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    // You can implement password reset email here similar to verification email

    res.json({ 
      success: true, 
      message: 'If an account with that email exists, a reset link has been sent.' 
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    success: false, 
    message: 'Internal server error' 
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'Endpoint not found',
    availableEndpoints: [
      'GET /',
      'GET /api/health',
      'POST /api/test-email',
      'POST /api/auth/register',
      'POST /api/auth/login',
      'GET /api/auth/verify/:token',
      'GET /api/user/profile',
      'PUT /api/user/profile'
    ]
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Base URL: https://kaushbackendcode-production.up.railway.app`);
  console.log(`🏥 Health check: https://kaushbackendcode-production.up.railway.app/api/health`);
  console.log(`🧪 Test email: POST https://kaushbackendcode-production.up.railway.app/api/test-email`);
  console.log('✅ Server startup complete');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
  });
});

module.exports = app;
