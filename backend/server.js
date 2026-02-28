require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// ========================================
// CRITICAL: PORT CONFIGURATION
// ========================================

const PORT = process.env.PORT || 3000;

console.log('='.repeat(50));
console.log('🚀 ClassicFlims Backend Starting...');
console.log('📍 Port:', PORT);
console.log('='.repeat(50));

// ========================================
// MIDDLEWARE
// ========================================

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ========================================
// SERVE STATIC FILES (public/admin.html)
// ========================================
const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));

// Admin panel routes — all serve admin.html
app.get('/admin',        (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/admin/login',  (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/admin/*',      (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// Logging middleware
app.use((req, res, next) => {
    console.log(`${req.method} ${req.path}`);
    next();
});

// ========================================
// ENVIRONMENT VARIABLES
// ========================================

const MONGOTESTDB_URI = process.env.MONGODB_URI;
 
const JWT_SECRET = process.env.JWT_SECRET || 'default-secret-change-me';

console.log('🔧 MongoDB URI:', MONGOTESTDB_URI ? '✓ Set' : '✗ Missing');
console.log('🔧 JWT Secret:', JWT_SECRET ? '✓ Set' : '✗ Missing');

// ========================================
// MONGODB CONNECTION
// ========================================

let isMongoConnected = false;

if (MONGOTESTDB_URI) {
    console.log('🔄 Connecting to MongoDB...');
    mongoose.connect(MONGOTESTDB_URI, {
        serverSelectionTimeoutMS: 30000, // 30 seconds timeout
        socketTimeoutMS: 45000,
    })
        .then(() => {
            isMongoConnected = true;
            console.log('✅ MongoDB Connected');
            console.log('📊 Database:', mongoose.connection.name);
        })
        .catch((error) => {
            console.error('❌ MongoDB Error:', error.message);
            console.error('💡 Tip: Check your MONGO_URI in .env file');
        });
    
    // Handle connection errors after initial connection
    mongoose.connection.on('error', (err) => {
        console.error('❌ MongoDB connection error:', err);
        isMongoConnected = false;
    });
    
    mongoose.connection.on('disconnected', () => {
        console.warn('⚠️  MongoDB disconnected');
        isMongoConnected = false;
    });
    
    mongoose.connection.on('reconnected', () => {
        console.log('✅ MongoDB reconnected');
        isMongoConnected = true;
    });
} else {
    console.warn('⚠️  No MongoDB URI - running without database');
}

// Helper function to ensure MongoDB is connected
async function ensureMongoConnection() {
    if (!MONGOTESTDB_URI) {
        throw new Error('MongoDB URI not configured');
    }
    
    // If already connected, return immediately
    if (mongoose.connection.readyState === 1) {
        return true;
    }
    
    // Wait for connection with timeout
    const timeout = 30000; // 30 seconds
    const startTime = Date.now();
    
    while (mongoose.connection.readyState !== 1) {
        if (Date.now() - startTime > timeout) {
            throw new Error('MongoDB connection timeout. Please check your MONGO_URI and network connection.');
        }
        // Wait 100ms before checking again
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    return true;
}

// ========================================
// SCHEMAS
// ========================================

const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'admin' },
    createdAt: { type: Date, default: Date.now }
});

// ========================================
// USER SCHEMA - ADD THIS WITH OTHER SCHEMAS
// ========================================
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' },
    subscription: { type: String, default: 'free', enum: ['free', 'premium'] },
    subscriptionExpiry: { type: Date },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date }
});

const contentSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: String,
    type: { type: String, enum: ['movie', 'series', 'documentary', 'live'], required: true },
    category: String,
    language: String,
    year: Number,
    duration: String,
    rating: Number,
    videoUrl: { type: String, required: true },
    thumbnailUrl: String,
    featured: { type: Boolean, default: false },
    trending: { type: Boolean, default: false },
    status: { type: String, enum: ['published', 'draft', 'archived'], default: 'published' },
    views: { type: Number, default: 0 },
    likes: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const navigationSchema = new mongoose.Schema({
    label: { type: String, required: true },
    url: { type: String, required: true },
    icon: String,
    order: { type: Number, default: 0 },
    active: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const advertisementSchema = new mongoose.Schema({
    title: { type: String, required: true },
    type: { type: String, enum: ['banner', 'video', 'popup'], default: 'banner' },
    position: { type: String, enum: ['header', 'sidebar', 'footer', 'player'], default: 'header' },
    imageUrl: { type: String, required: true },
    clickUrl: String,
    priority: { type: Number, default: 5 },
    active: { type: Boolean, default: true },
    impressions: { type: Number, default: 0 },
    clicks: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

const settingsSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    value: mongoose.Schema.Types.Mixed,
    category: { type: String, default: 'general' },
    description: String,
    updatedAt: { type: Date, default: Date.now }
});

const contactSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true, maxlength: 100 },
    email: { type: String, required: true, trim: true, lowercase: true },
    subject: { type: String, required: true, trim: true, maxlength: 200 },
    message: { type: String, required: true, trim: true, maxlength: 2000 },
    status: { type: String, enum: ['new', 'read', 'replied', 'archived'], default: 'new' },
    ip: { type: String },
    userAgent: { type: String },
    createdAt: { type: Date, default: Date.now },
    repliedAt: { type: Date },
    notes: { type: String }
});

const Admin = mongoose.model('Admin', adminSchema);
// ADD USER MODEL WITH OTHER MODELS
const User = mongoose.model('User', userSchema);
const Content = mongoose.model('Content', contentSchema);
const Navigation = mongoose.model('Navigation', navigationSchema);
const Advertisement = mongoose.model('Advertisement', advertisementSchema);
const Settings = mongoose.model('Settings', settingsSchema);
const Contact = mongoose.model('Contact', contactSchema);

// ========================================
// AUTH MIDDLEWARE
// ========================================

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.admin = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// ========================================
// BASIC ROUTES
// ========================================

app.get('/', (req, res) => {
    res.json({
        message: 'ClassicFlims Backend API',
        version: '1.0.0',
        status: 'running',
        timestamp: new Date().toISOString(),
        endpoints: {
            health: '/health',
            api: '/api',
            admin_login: '/api/admin/login',
            content: '/api/content',
            navigation: '/api/navigation',
            advertisements: '/api/advertisements',
            settings: '/api/settings',
            seed: '/api/seed'
        }
    });
});

app.get('/health', async (req, res) => {
    const dbState = mongoose.connection.readyState;
    const dbStatus = {
        0: 'disconnected',
        1: 'connected',
        2: 'connecting',
        3: 'disconnecting'
    };
    
    const health = {
        status: dbState === 1 ? 'ok' : 'degraded',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        database: {
            status: dbStatus[dbState] || 'unknown',
            connected: dbState === 1,
            name: mongoose.connection.name || 'N/A'
        },
        port: PORT,
        mongoUri: MONGOTESTDB_URI ? 'configured' : 'missing'
    };
    
    // Try a simple DB operation if connected
    if (dbState === 1) {
        try {
            await mongoose.connection.db.admin().ping();
            health.database.ping = 'success';
        } catch (error) {
            health.database.ping = 'failed';
            health.database.error = error.message;
        }
    }
    
    const statusCode = dbState === 1 ? 200 : 503;
    res.status(statusCode).json(health);
});

// ========================================
// USER AUTH ROUTES
// ========================================

// User Registration (Sign Up)
app.post('/api/users/register', async (req, res) => {
    try {
        console.log('📝 Registration attempt:', req.body.email);
        
        const { name, email, password } = req.body;
        
        // Validation
        if (!name || !email || !password) {
            return res.status(400).json({ 
                success: false,
                error: 'Name, email and password are required' 
            });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ 
                success: false,
                error: 'Password must be at least 6 characters' 
            });
        }
        
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ 
                success: false,
                error: 'Email already registered' 
            });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const user = await User.create({
            name,
            email,
            password: hashedPassword,
            role: 'user'
        });
        
        // Generate token
        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '30d' }
        );
        
        console.log('✅ User registered:', user.email);
        
        res.status(201).json({
            success: true,
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
        
    } catch (error) {
        console.error('❌ Registration error:', error);
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// User Login (Sign In)
app.post('/api/users/login', async (req, res) => {
    try {
        console.log('🔐 User login attempt:', req.body.email);
        
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ 
                success: false,
                error: 'Email and password required' 
            });
        }
        
        // Find user
        const user = await User.findOne({ email });
        
        if (!user) {
            console.log('❌ User not found');
            return res.status(401).json({ 
                success: false,
                error: 'Invalid credentials' 
            });
        }
        
        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            console.log('❌ Invalid password');
            return res.status(401).json({ 
                success: false,
                error: 'Invalid credentials' 
            });
        }
        
        // Generate token
        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '30d' }
        );
        
        console.log('✅ User login successful');
        
        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
        
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// Get current user info (optional - for profile)
app.get('/api/users/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json({ success: true, user });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// CONTACT FORM ROUTES
// ========================================

// Rate limiting storage (in-memory - use Redis in production)
const contactSubmissions = new Map();

// Clean up old entries every hour
setInterval(() => {
    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    for (const [ip, timestamp] of contactSubmissions.entries()) {
        if (timestamp < oneHourAgo) {
            contactSubmissions.delete(ip);
        }
    }
}, 60 * 60 * 1000);

// Submit contact form
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, subject, message } = req.body;
        
        // Get client IP
        const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || 
                        req.socket.remoteAddress || 
                        'unknown';

        // Rate limiting: 1 submission per IP per hour
        const lastSubmission = contactSubmissions.get(clientIp);
        const oneHourAgo = Date.now() - (60 * 60 * 1000);
        
        if (lastSubmission && lastSubmission > oneHourAgo) {
            return res.status(429).json({
                success: false,
                error: 'Too many requests. Please wait an hour before submitting again.'
            });
        }

        // Validation
        if (!name || !email || !subject || !message) {
            return res.status(400).json({
                success: false,
                error: 'All fields are required'
            });
        }

        // Length validation
        if (name.length < 2 || name.length > 100) {
            return res.status(400).json({
                success: false,
                error: 'Name must be between 2 and 100 characters'
            });
        }

        if (subject.length < 3 || subject.length > 200) {
            return res.status(400).json({
                success: false,
                error: 'Subject must be between 3 and 200 characters'
            });
        }

        if (message.length < 10 || message.length > 2000) {
            return res.status(400).json({
                success: false,
                error: 'Message must be between 10 and 2000 characters'
            });
        }

        // Email format validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid email address'
            });
        }

        // Spam detection: Check for suspicious patterns
        const spamPatterns = [
            /viagra/i,
            /cialis/i,
            /pharmacy/i,
            /casino/i,
            /lottery/i,
            /bitcoin/i,
            /crypto/i,
            /invest now/i,
            /click here/i,
            /buy now/i,
            /<script/i,
            /<iframe/i
        ];

        const combinedText = `${name} ${subject} ${message}`.toLowerCase();
        const isSpam = spamPatterns.some(pattern => pattern.test(combinedText));

        if (isSpam) {
            console.log('Spam detected:', { name, email, subject });
            // Silently reject spam
            return res.status(400).json({
                success: false,
                error: 'Your message could not be sent. Please contact us directly.'
            });
        }

        // Create contact submission
        const contact = await Contact.create({
            name: name.trim(),
            email: email.trim().toLowerCase(),
            subject: subject.trim(),
            message: message.trim(),
            ip: clientIp,
            userAgent: req.headers['user-agent'] || 'unknown',
            status: 'new'
        });

        // Update rate limiting
        contactSubmissions.set(clientIp, Date.now());

        console.log('✅ New contact submission:', { 
            id: contact._id, 
            name: contact.name, 
            email: contact.email,
            ip: clientIp
        });

        res.status(201).json({
            success: true,
            message: 'Thank you for your message! We will get back to you soon.',
            id: contact._id
        });

    } catch (error) {
        console.error('❌ Contact submission error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to submit your message. Please try again later.'
        });
    }
});

// Get all contact submissions (admin only)
app.get('/api/contact', authMiddleware, async (req, res) => {
    try {
        const { status, page = 1, limit = 50 } = req.query;
        const query = {};
        
        if (status && status !== 'all') {
            query.status = status;
        }

        const contacts = await Contact.find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));

        const total = await Contact.countDocuments(query);

        res.json({
            success: true,
            contacts,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get single contact submission (admin only)
app.get('/api/contact/:id', authMiddleware, async (req, res) => {
    try {
        const contact = await Contact.findById(req.params.id);
        if (!contact) {
            return res.status(404).json({ success: false, error: 'Contact not found' });
        }

        // Mark as read if status is 'new'
        if (contact.status === 'new') {
            contact.status = 'read';
            await contact.save();
        }

        res.json({ success: true, contact });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Update contact status (admin only)
app.put('/api/contact/:id', authMiddleware, async (req, res) => {
    try {
        const { status, notes } = req.body;
        const contact = await Contact.findById(req.params.id);
        
        if (!contact) {
            return res.status(404).json({ success: false, error: 'Contact not found' });
        }

        if (status) contact.status = status;
        if (notes !== undefined) contact.notes = notes;
        if (status === 'replied') contact.repliedAt = new Date();

        await contact.save();

        res.json({ success: true, contact });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Delete contact submission (admin only)
app.delete('/api/contact/:id', authMiddleware, async (req, res) => {
    try {
        const contact = await Contact.findByIdAndDelete(req.params.id);
        if (!contact) {
            return res.status(404).json({ success: false, error: 'Contact not found' });
        }
        res.json({ success: true, message: 'Contact deleted' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// ADMIN AUTH
// ========================================

app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const admin = await Admin.findOne({ username });
        if (!admin) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign(
            { id: admin._id, username: admin.username, role: admin.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        res.json({
            token,
            admin: {
                id: admin._id,
                username: admin.username,
                email: admin.email,
                role: admin.role
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// CONTENT ROUTES
// ========================================

app.get('/api/content', async (req, res) => {
    try {
        const { category, type, status, search, page = 1, limit = 20} = req.query;
        const query = {};
        if (category) query.category = category;
        if (type) query.type = type;
        if (status && status !== 'all') query.status = status;
        else if (!status) query.status = 'published';
        // if status=all, no filter - shows all records for admin
        if (search) query.title = { $regex: search, $options: 'i' };
        
        const content = await Content.find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));
        
        const total = await Content.countDocuments(query);
        
        res.json({
            content,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/content/:id', async (req, res) => {
    try {
        const content = await Content.findById(req.params.id);
        if (!content) return res.status(404).json({ error: 'Content not found' });
        res.json(content);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/content', authMiddleware, async (req, res) => {
    try {
        const content = await Content.create(req.body);
        res.status(201).json(content);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/api/content/:id', authMiddleware, async (req, res) => {
    try {
        const content = await Content.findByIdAndUpdate(
            req.params.id,
            { ...req.body, updatedAt: Date.now() },
            { new: true }
        );
        if (!content) return res.status(404).json({ error: 'Content not found' });
        res.json(content);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/content/:id', authMiddleware, async (req, res) => {
    try {
        const content = await Content.findByIdAndDelete(req.params.id);
        if (!content) return res.status(404).json({ error: 'Content not found' });
        res.json({ message: 'Content deleted' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// NAVIGATION ROUTES
// ========================================

app.get('/api/navigation', async (req, res) => {
    try {
        const navigation = await Navigation.find({ active: true }).sort({ order: 1 });
        res.json(navigation);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/navigation', authMiddleware, async (req, res) => {
    try {
        const navigation = await Navigation.create(req.body);
        res.status(201).json(navigation);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/api/navigation/:id', authMiddleware, async (req, res) => {
    try {
        const nav = await Navigation.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!nav) return res.status(404).json({ error: 'Navigation not found' });
        res.json(nav);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/navigation/:id', authMiddleware, async (req, res) => {
    try {
        await Navigation.findByIdAndDelete(req.params.id);
        res.json({ message: 'Navigation deleted' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// ADVERTISEMENT ROUTES
// ========================================

app.get('/api/advertisements', async (req, res) => {
    try {
        // Return all ads - admin needs to see inactive ones too
        const ads = await Advertisement.find().sort({ priority: -1, createdAt: -1 });
        res.json(ads);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/advertisements', authMiddleware, async (req, res) => {
    try {
        const ad = await Advertisement.create(req.body);
        res.status(201).json(ad);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/api/advertisements/:id', authMiddleware, async (req, res) => {
    try {
        const ad = await Advertisement.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!ad) return res.status(404).json({ error: 'Ad not found' });
        res.json(ad);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/advertisements/:id', authMiddleware, async (req, res) => {
    try {
        await Advertisement.findByIdAndDelete(req.params.id);
        res.json({ message: 'Ad deleted' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// SETTINGS ROUTES
// ========================================

app.get('/api/settings', async (req, res) => {
    try {
        const settings = await Settings.find();
        res.json(settings);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/settings', authMiddleware, async (req, res) => {
    try {
        const setting = await Settings.findOneAndUpdate(
            { key: req.body.key },
            { ...req.body, updatedAt: Date.now() },
            { upsert: true, new: true }
        );
        res.json(setting);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ========================================
// DASHBOARD STATS
// ========================================

app.put('/api/settings/:id', authMiddleware, async (req, res) => {
    try {
        const setting = await Settings.findByIdAndUpdate(
            req.params.id,
            { ...req.body, updatedAt: Date.now() },
            { new: true }
        );
        if (!setting) return res.status(404).json({ error: 'Setting not found' });
        res.json(setting);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/settings/:id', authMiddleware, async (req, res) => {
    try {
        await Settings.findByIdAndDelete(req.params.id);
        res.json({ message: 'Setting deleted' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
    try {
        const totalContent = await Content.countDocuments();
        const publishedContent = await Content.countDocuments({ status: 'published' });
        const totalAds = await Advertisement.countDocuments({ active: true });
        const totalViews = await Content.aggregate([
            { $group: { _id: null, total: { $sum: '$views' } } }
        ]);
        const totalLikes = await Content.aggregate([
            { $group: { _id: null, total: { $sum: '$likes' } } }
        ]);
        res.json({
            totalContent,
            publishedContent,
            totalAds,
            totalViews: totalViews[0]?.total || 0,
            totalLikes: totalLikes[0]?.total || 0
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// SEED ROUTE
// ========================================

app.post('/api/seed', async (req, res) => {
    try {
        console.log('🌱 Starting seed...');
        
        // Quick connection check
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({
                error: 'Database not connected. Please wait a moment and try again.',
                mongoState: mongoose.connection.readyState
            });
        }
        
        console.log('✅ MongoDB is connected, proceeding with seed...');
        
        // Respond IMMEDIATELY to prevent timeout
        res.json({
            message: '✅ Seeding started successfully!',
            status: 'processing',
            info: 'Data is being inserted. Check /api/seed/status or /api/content to verify.',
            timestamp: new Date().toISOString()
        });
        
        // ============================================
        // PROCESS SEED IN BACKGROUND (ASYNC)
        // ============================================
        
        setImmediate(async () => {
            try {
                console.log('📦 Background seeding started...');
                const startTime = Date.now();
                
                // ── Admin ──────────────────────────────────────────────
                const adminCount = await Admin.countDocuments();
                if (adminCount === 0) {
                    const hashedPassword = await bcrypt.hash('admin123', 10);
                    await Admin.create({
                        username: 'admin',
                        email: 'admin@classicflims.com',
                        password: hashedPassword,
                        role: 'admin'
                    });
                    console.log('✅ Admin created (admin / admin123)');
                }

                // ── Navigation ─────────────────────────────────────────
                await Navigation.deleteMany({});
                await Navigation.insertMany([
                    { label: 'Home', url: '/', icon: '🏠', order: 0, active: true },
                    { label: 'Movies', url: '/movies', icon: '🎬', order: 1, active: true },
                    { label: 'Series', url: '/series', icon: '📺', order: 2, active: true },
                    { label: 'Documentaries', url: '/documentaries', icon: '📽️', order: 3, active: true },
                    { label: 'Live', url: '/live', icon: '🔴', order: 4, active: true }
                ]);
                console.log('✅ Navigation created (5 items)');

                // ── Settings ───────────────────────────────────────────
                await Settings.deleteMany({});
                await Settings.insertMany([
                    { key: 'site_name', value: 'ClassicFlims', category: 'general' },
                    { key: 'site_tagline', value: 'PREMIUM CLASSIC CINEMA', category: 'general' },
                    { key: 'primary_color', value: '#ff3366', category: 'theme' },
                    { key: 'secondary_color', value: '#7c3aed', category: 'theme' }
                ]);
                console.log('✅ Settings created (4 items)');

                // ── Content (40 items) ─────────────────────────────────
                const force = req.query.force === 'true';
                const contentCount = await Content.countDocuments();
                
                if (contentCount === 0 || force) {
                    if (force && contentCount > 0) {
                        console.log('⚠️ Force mode: Deleting existing content...');
                        await Content.deleteMany({});
                    }
                    
                    console.log('📦 Inserting 40 movies in chunks...');
                    
                    // Insert options for better performance
                    const insertOptions = {
                        ordered: false,
                        writeConcern: { w: 1, wtimeout: 60000 }
                    };
                    
                    await Content.insertMany([

        // ================================================
        // FAMOUS MOVIES 1950-1970 — YouTube Embeds
        // 40 items: 10 Drama + 10 Thriller + 10 Western + 10 Romance/Musical
        // ================================================

        // DRAMA MOVIES (10 items)
        {
          title: "12 Angry Men (1957)",
          description: "Sidney Lumet's masterpiece. A jury deliberates the fate of a young man accused of murder. One dissenting juror slowly convinces others to reconsider. Henry Fonda leads an ensemble cast in this claustrophobic courtroom drama. 96% on Rotten Tomatoes. AFI's #2 Courtroom Drama.",
          type: "movie",
          category: "Drama",
          language: "English",
          year: 1957,
          duration: "96 min",
          rating: 9.0,
          videoUrl: "https://www.youtube.com/embed/TEN-2uTi2c0",
          thumbnailUrl: "https://img.youtube.com/vi/TEN-2uTi2c0/maxresdefault.jpg",
          featured: true,
          trending: true,
          status: "published",
          views: 125000,
          likes: 118000
        },
        {
          title: "To Kill a Mockingbird (1962)",
          description: "Gregory Peck as Atticus Finch defending a Black man falsely accused in Depression-era Alabama. Harper Lee adaptation directed by Robert Mulligan. Peck won Best Actor Oscar. American Film Institute's #1 Hero (Atticus Finch). A profound meditation on racism and justice.",
          type: "movie",
          category: "Drama",
          language: "English",
          year: 1962,
          duration: "129 min",
          rating: 8.3,
          videoUrl: "https://www.youtube.com/embed/KR7loA_oziY",
          thumbnailUrl: "https://img.youtube.com/vi/KR7loA_oziY/maxresdefault.jpg",
          featured: true,
          trending: true,
          status: "published",
          views: 98000,
          likes: 89000
        },
        {
          title: "The Apartment (1960)",
          description: "Billy Wilder's bittersweet comedy-drama. Jack Lemmon as a lonely office worker who lends his apartment to executives for affairs. Shirley MacLaine as the elevator operator he loves. Won 5 Oscars including Best Picture and Director. A perfect blend of humor and heartache.",
          type: "movie",
          category: "Drama",
          language: "English",
          year: 1960,
          duration: "125 min",
          rating: 8.2,
          videoUrl: "https://www.youtube.com/embed/KqMdHmOREcw",
          thumbnailUrl: "https://img.youtube.com/vi/KqMdHmOREcw/maxresdefault.jpg",
          featured: true,
          trending: false,
          status: "published",
          views: 67000,
          likes: 59000
        },
        {
          title: "On the Waterfront (1954)",
          description: "Elia Kazan's gritty drama about mob-controlled docks. Marlon Brando as ex-boxer Terry Malloy who becomes an informant. 'I coulda been a contender' - one of cinema's most famous lines. Won 8 Oscars including Best Picture and Actor (Brando). Method acting at its finest.",
          type: "movie",
          category: "Drama",
          language: "English",
          year: 1954,
          duration: "108 min",
          rating: 8.1,
          videoUrl: "https://www.youtube.com/embed/l2gMJRzARhQ",
          thumbnailUrl: "https://img.youtube.com/vi/l2gMJRzARhQ/maxresdefault.jpg",
          featured: false,
          trending: true,
          status: "published",
          views: 54000,
          likes: 47000
        },
        {
          title: "A Streetcar Named Desire (1951)",
          description: "Tennessee Williams' masterpiece brought to screen by Elia Kazan. Vivien Leigh as fragile Blanche DuBois, Marlon Brando as brutal Stanley Kowalski. 'STELLA!' echoes through cinema history. Won 4 Oscars. Raw emotional power and Southern Gothic atmosphere.",
          type: "movie",
          category: "Drama",
          language: "English",
          year: 1951,
          duration: "122 min",
          rating: 7.9,
          videoUrl: "https://www.youtube.com/embed/SblQXpw24_g",
          thumbnailUrl: "https://img.youtube.com/vi/SblQXpw24_g/maxresdefault.jpg",
          featured: false,
          trending: false,
          status: "published",
          views: 48000,
          likes: 41000
        },
        {
          title: "The Graduate (1967)",
          description: "Mike Nichols' defining film of 1960s alienation. Dustin Hoffman as Benjamin Braddock seduced by Mrs. Robinson (Anne Bancroft), then falling for her daughter. Simon & Garfunkel soundtrack. 'Plastics.' Won Best Director Oscar. Cultural phenomenon.",
          type: "movie",
          category: "Drama",
          language: "English",
          year: 1967,
          duration: "106 min",
          rating: 8.0,
          videoUrl: "https://www.youtube.com/embed/hsdvhJTqLakk",
          thumbnailUrl: "https://img.youtube.com/vi/hsdvhJTqLakk/maxresdefault.jpg",
          featured: true,
          trending: true,
          status: "published",
          views: 89000,
          likes: 78000
        },
        {
          title: "Cool Hand Luke (1967)",
          description: "Paul Newman as the rebellious prisoner who refuses to conform. 'What we've got here is failure to communicate.' Stuart Rosenberg's prison drama is both a character study and a Christ allegory. Newman's iconic performance. Egg-eating scene is legendary.",
          type: "movie",
          category: "Drama",
          language: "English",
          year: 1967,
          duration: "126 min",
          rating: 8.1,
          videoUrl: "https://www.youtube.com/embed/452XjnaHr1A",
          thumbnailUrl: "https://img.youtube.com/vi/452XjnaHr1A/maxresdefault.jpg",
          featured: false,
          trending: true,
          status: "published",
          views: 63000,
          likes: 55000
        },
        {
          title: "Who's Afraid of Virginia Woolf? (1966)",
          description: "Mike Nichols' explosive debut. Elizabeth Taylor and Richard Burton as a bitter married couple tearing each other apart. Edward Albee adaptation. Taylor won her second Oscar. Four people, one night, brutal honesty. 'Get the guests!' A masterclass in acting.",
          type: "movie",
          category: "Drama",
          language: "English",
          year: 1966,
          duration: "131 min",
          rating: 8.0,
          videoUrl: "https://www.youtube.com/embed/8JjCW_wYP6o",
          thumbnailUrl: "https://img.youtube.com/vi/8JjCW_wYP6o/maxresdefault.jpg",
          featured: false,
          trending: false,
          status: "published",
          views: 41000,
          likes: 36000
        },
        {
          title: "Rebel Without a Cause (1955)",
          description: "Nicholas Ray's teen angst classic. James Dean's most iconic role as troubled Jim Stark. 'You're tearing me apart!' Natalie Wood and Sal Mineo complete the trio. Dean died weeks before release. A defining portrait of 1950s youth alienation.",
          type: "movie",
          category: "Drama",
          language: "English",
          year: 1955,
          duration: "111 min",
          rating: 7.6,
          videoUrl: "https://www.youtube.com/embed/gkH2y3VuwVs",
          thumbnailUrl: "https://img.youtube.com/vi/gkH2y3VuwVs/maxresdefault.jpg",
          featured: true,
          trending: false,
          status: "published",
          views: 71000,
          likes: 62000
        },
        {
          title: "The Bridge on the River Kwai (1957)",
          description: "David Lean's epic war drama. British POWs forced to build a bridge for Japanese in Burma. Alec Guinness as Colonel Nicholson obsessed with pride. William Holden plans to destroy it. Won 7 Oscars including Best Picture. 'Madness! Madness!'",
          type: "movie",
          category: "Drama",
          language: "English",
          year: 1957,
          duration: "161 min",
          rating: 8.1,
          videoUrl: "https://www.youtube.com/embed/Y7vVVJTPbKo",
          thumbnailUrl: "https://img.youtube.com/vi/Y7vVVJTPbKo/maxresdefault.jpg",
          featured: true,
          trending: false,
          status: "published",
          views: 58000,
          likes: 51000
        },

        // THRILLER/MYSTERY MOVIES (10 items)
        {
          title: "Psycho (1960)",
          description: "Alfred Hitchcock's horror masterpiece. Janet Leigh checks into Bates Motel, meets Norman Bates (Anthony Perkins). The shower scene redefined cinema violence. Bernard Herrmann's screeching strings. 'A boy's best friend is his mother.' Revolutionary narrative structure.",
          type: "movie",
          category: "Thriller",
          language: "English",
          year: 1960,
          duration: "109 min",
          rating: 8.5,
          videoUrl: "https://www.youtube.com/embed/Wz719b9QUqY",
          thumbnailUrl: "https://img.youtube.com/vi/Wz719b9QUqY/maxresdefault.jpg",
          featured: true,
          trending: true,
          status: "published",
          views: 156000,
          likes: 142000
        },
        {
          title: "Vertigo (1958)",
          description: "Hitchcock's masterpiece of obsession. James Stewart as detective with acrophobia hired to follow Kim Novak. Spiraling into madness and desire. Bernard Herrmann score. Initially mixed reviews, now considered greatest film ever made by critics. The ultimate film about filmmaking.",
          type: "movie",
          category: "Thriller",
          language: "English",
          year: 1958,
          duration: "128 min",
          rating: 8.3,
          videoUrl: "https://www.youtube.com/embed/jv-o3fv4Y5M",
          thumbnailUrl: "https://img.youtube.com/vi/jv-o3fv4Y5M/maxresdefault.jpg",
          featured: true,
          trending: true,
          status: "published",
          views: 94000,
          likes: 83000
        },
        {
          title: "North by Northwest (1959)",
          description: "Hitchcock's chase thriller. Cary Grant mistaken for a spy, pursued across America. Eva Marie Saint, James Mason. Mount Rushmore climax. Crop duster sequence. Saul Bass titles. Bernard Herrmann score. Peak Hitchcock entertainment - witty, suspenseful, stylish.",
          type: "movie",
          category: "Thriller",
          language: "English",
          year: 1959,
          duration: "136 min",
          rating: 8.3,
          videoUrl: "https://www.youtube.com/embed/MGX-v8SX8kk",
          thumbnailUrl: "https://img.youtube.com/vi/MGX-v8SX8kk/maxresdefault.jpg",
          featured: true,
          trending: false,
          status: "published",
          views: 81000,
          likes: 72000
        },
        {
          title: "Rear Window (1954)",
          description: "Hitchcock's voyeuristic masterpiece. James Stewart wheelchair-bound, spying on neighbors, witnesses murder. Grace Kelly as his glamorous girlfriend. Apartment courtyard set is legendary. Tense, ethical, perfectly constructed. Cinema about cinema.",
          type: "movie",
          category: "Thriller",
          language: "English",
          year: 1954,
          duration: "112 min",
          rating: 8.5,
          videoUrl: "https://www.youtube.com/embed/0irWZywdJl4",
          thumbnailUrl: "https://img.youtube.com/vi/0irWZywdJl4/maxresdefault.jpg",
          featured: true,
          trending: true,
          status: "published",
          views: 102000,
          likes: 91000
        },
        {
          title: "The Birds (1963)",
          description: "Hitchcock's apocalyptic horror. Birds inexplicably attack a California town. Tippi Hedren's debut. No explanation given for the attacks. Pioneering special effects. Bernard Herrmann electronic soundtrack. Jungle gym scene still terrifies. Ambiguous ending.",
          type: "movie",
          category: "Thriller",
          language: "English",
          year: 1963,
          duration: "119 min",
          rating: 7.6,
          videoUrl: "https://www.youtube.com/embed/hplpQt424Ls",
          thumbnailUrl: "https://img.youtube.com/vi/hplpQt424Ls/maxresdefault.jpg",
          featured: false,
          trending: true,
          status: "published",
          views: 73000,
          likes: 64000
        },
        {
          title: "The Manchurian Candidate (1962)",
          description: "John Frankenheimer's political thriller. Korean War vet (Laurence Harvey) brainwashed to be assassin. Frank Sinatra tries to stop him. Angela Lansbury as terrifying mother. Ahead of its time. Pulled from theaters after JFK assassination. Paranoid Cold War masterpiece.",
          type: "movie",
          category: "Thriller",
          language: "English",
          year: 1962,
          duration: "126 min",
          rating: 7.9,
          videoUrl: "https://www.youtube.com/embed/HK5OsDWYJmQ",
          thumbnailUrl: "https://img.youtube.com/vi/HK5OsDWYJmQ/maxresdefault.jpg",
          featured: false,
          trending: false,
          status: "published",
          views: 52000,
          likes: 45000
        },
        {
          title: "Touch of Evil (1958)",
          description: "Orson Welles' noir masterpiece. Charlton Heston as Mexican narcotics officer, Welles as corrupt American cop. Opening tracking shot is legendary (3 minutes 20 seconds). Marlene Dietrich, Janet Leigh. Dark, baroque, expressionistic. Welles' last great Hollywood film.",
          type: "movie",
          category: "Thriller",
          language: "English",
          year: 1958,
          duration: "95 min",
          rating: 8.0,
          videoUrl: "https://www.youtube.com/embed/Yg8MqjoFvy4",
          thumbnailUrl: "https://img.youtube.com/vi/Yg8MqjoFvy4/maxresdefault.jpg",
          featured: false,
          trending: false,
          status: "published",
          views: 46000,
          likes: 39000
        },
        {
          title: "Wait Until Dark (1967)",
          description: "Terence Young's claustrophobic thriller. Audrey Hepburn as blind woman terrorized by drug dealers in her apartment. Alan Arkin as psychotic villain. Unbearably tense finale in darkness. Hepburn Oscar-nominated. Based on Frederick Knott play.",
          type: "movie",
          category: "Thriller",
          language: "English",
          year: 1967,
          duration: "108 min",
          rating: 7.7,
          videoUrl: "https://www.youtube.com/embed/FYnRHbKiEPQ",
          thumbnailUrl: "https://img.youtube.com/vi/FYnRHbKiEPQ/maxresdefault.jpg",
          featured: false,
          trending: false,
          status: "published",
          views: 38000,
          likes: 32000
        },
        {
          title: "The Third Man (1949)",
          description: "Carol Reed's noir set in post-war Vienna. Joseph Cotten searches for his friend Harry Lime (Orson Welles). Iconic zither score. Sewer chase. 'The cuckoo clock' speech. Graham Greene screenplay. Expressionistic camerawork. Welles appears at 1-hour mark.",
          type: "movie",
          category: "Thriller",
          language: "English",
          year: 1949,
          duration: "104 min",
          rating: 8.1,
          videoUrl: "https://www.youtube.com/embed/Vv4OzQ0YaDQ",
          thumbnailUrl: "https://img.youtube.com/vi/Vv4OzQ0YaDQ/maxresdefault.jpg",
          featured: true,
          trending: false,
          status: "published",
          views: 61000,
          likes: 54000
        },
        {
          title: "Diabolique (1955)",
          description: "Henri-Georges Clouzot's French thriller. Wife and mistress plot to murder abusive headmaster. Body disappears. Twists and psychological terror. Influenced Hitchcock's Psycho. 'Don't be devils! Don't reveal the ending!' Simone Signoret, Véra Clouzot. Bathtub scene iconic.",
          type: "movie",
          category: "Thriller",
          language: "French",
          year: 1955,
          duration: "117 min",
          rating: 8.1,
          videoUrl: "https://www.youtube.com/embed/v39YIcZw0eI",
          thumbnailUrl: "https://img.youtube.com/vi/v39YIcZw0eI/maxresdefault.jpg",
          featured: false,
          trending: true,
          status: "published",
          views: 44000,
          likes: 38000
        },

        // WESTERN MOVIES (10 items)
        {
          title: "The Good, the Bad and the Ugly (1966)",
          description: "Sergio Leone's epic Spaghetti Western. Clint Eastwood, Lee Van Cleef, Eli Wallach hunt buried gold during Civil War. Ennio Morricone's iconic score. Three-way standoff finale. Extreme close-ups. 3-hour masterpiece. Greatest Western ever made according to many critics.",
          type: "movie",
          category: "Western",
          language: "English",
          year: 1966,
          duration: "178 min",
          rating: 8.8,
          videoUrl: "https://www.youtube.com/embed/IFNUGzCOQoI",
          thumbnailUrl: "https://img.youtube.com/vi/IFNUGzCOQoI/maxresdefault.jpg",
          featured: true,
          trending: true,
          status: "published",
          views: 167000,
          likes: 153000
        },
        {
          title: "The Searchers (1956)",
          description: "John Ford's masterpiece. John Wayne as Ethan Edwards on years-long quest to find niece captured by Comanches. Monument Valley. Complex portrayal of racism and obsession. 'That'll be the day.' Influenced countless filmmakers from Scorsese to Lucas. AFI's Greatest Western.",
          type: "movie",
          category: "Western",
          language: "English",
          year: 1956,
          duration: "119 min",
          rating: 7.8,
          videoUrl: "https://www.youtube.com/embed/9K7JyHHn64w",
          thumbnailUrl: "https://img.youtube.com/vi/9K7JyHHn64w/maxresdefault.jpg",
          featured: true,
          trending: false,
          status: "published",
          views: 78000,
          likes: 68000
        },
        {
          title: "Once Upon a Time in the West (1968)",
          description: "Sergio Leone's operatic Western. Charles Bronson as harmonica-playing gunslinger seeking revenge. Henry Fonda as cold-blooded killer. Claudia Cardinale. Ennio Morricone's greatest score. Epic Monument Valley cinematography. 15-minute opening wordless sequence. Pure cinema.",
          type: "movie",
          category: "Western",
          language: "English",
          year: 1968,
          duration: "165 min",
          rating: 8.5,
          videoUrl: "https://www.youtube.com/embed/c8CJ6L0I6W8",
          thumbnailUrl: "https://img.youtube.com/vi/c8CJ6L0I6W8/maxresdefault.jpg",
          featured: true,
          trending: true,
          status: "published",
          views: 121000,
          likes: 109000
        },
        {
          title: "High Noon (1952)",
          description: "Fred Zinnemann's real-time Western. Gary Cooper as marshal abandoned by town when outlaws arrive. Grace Kelly as Quaker wife. 'Do Not Forsake Me.' 85-minute runtime matches story time. Allegory for McCarthyism. Won 4 Oscars. Clinton's favorite film.",
          type: "movie",
          category: "Western",
          language: "English",
          year: 1952,
          duration: "85 min",
          rating: 8.0,
          videoUrl: "https://www.youtube.com/embed/hfWJaTp2dEw",
          thumbnailUrl: "https://img.youtube.com/vi/hfWJaTp2dEw/maxresdefault.jpg",
          featured: false,
          trending: true,
          status: "published",
          views: 64000,
          likes: 56000
        },
        {
          title: "The Magnificent Seven (1960)",
          description: "John Sturges' Western remake of Seven Samurai. Yul Brynner, Steve McQueen, Charles Bronson hired to defend Mexican village. Elmer Bernstein's rousing theme. Peak ensemble Western. Spawned sequels and TV series. McQueen's cool factor at maximum.",
          type: "movie",
          category: "Western",
          language: "English",
          year: 1960,
          duration: "128 min",
          rating: 7.7,
          videoUrl: "https://www.youtube.com/embed/6eE_xTu60xw",
          thumbnailUrl: "https://img.youtube.com/vi/6eE_xTu60xw/maxresdefault.jpg",
          featured: true,
          trending: false,
          status: "published",
          views: 87000,
          likes: 76000
        },
        {
          title: "Rio Bravo (1959)",
          description: "Howard Hawks' leisurely Western. John Wayne as sheriff holding prisoner, aided by Dean Martin (drunk), Ricky Nelson (young gun), Walter Brennan (cripple). Hawks' response to High Noon's pacifism. Angie Dickinson. 'Professional' filmmaking - character over plot.",
          type: "movie",
          category: "Western",
          language: "English",
          year: 1959,
          duration: "141 min",
          rating: 8.0,
          videoUrl: "https://www.youtube.com/embed/lIz10K7V6hI",
          thumbnailUrl: "https://img.youtube.com/vi/lIz10K7V6hI/maxresdefault.jpg",
          featured: false,
          trending: false,
          status: "published",
          views: 52000,
          likes: 45000
        },
        {
          title: "The Wild Bunch (1969)",
          description: "Sam Peckinpah's violent elegy for the Old West. Aging outlaws (William Holden, Ernest Borgnine) in 1913 Mexico. Graphic violence with slow-motion. 'If they move, kill 'em.' Final shootout is operatic bloodbath. Death of Western innocence. Controversial and influential.",
          type: "movie",
          category: "Western",
          language: "English",
          year: 1969,
          duration: "145 min",
          rating: 7.9,
          videoUrl: "https://www.youtube.com/embed/L-K0fHMF-u8",
          thumbnailUrl: "https://img.youtube.com/vi/L-K0fHMF-u8/maxresdefault.jpg",
          featured: true,
          trending: true,
          status: "published",
          views: 69000,
          likes: 60000
        },
        {
          title: "Butch Cassidy and the Sundance Kid (1969)",
          description: "George Roy Hill's buddy Western. Paul Newman and Robert Redford as charming outlaws. 'Raindrops Keep Fallin' on My Head.' Bolivia escape. Katharine Ross. Burt Bacharach score. Won 4 Oscars. Freeze-frame ending. New Hollywood cool with Old West setting.",
          type: "movie",
          category: "Western",
          language: "English",
          year: 1969,
          duration: "110 min",
          rating: 8.0,
          videoUrl: "https://www.youtube.com/embed/OO5y2O_hv3I",
          thumbnailUrl: "https://img.youtube.com/vi/OO5y2O_hv3I/maxresdefault.jpg",
          featured: true,
          trending: false,
          status: "published",
          views: 95000,
          likes: 83000
        },
        {
          title: "Shane (1953)",
          description: "George Stevens' mythic Western. Alan Ladd as mysterious gunfighter helping homesteaders. 'Shane! Come back!' Jack Palance as villain Wilson. Wyoming landscape. Loyal dog. Good vs evil in purest form. Jean Arthur, Van Heflin. Boy's-eye view makes it timeless.",
          type: "movie",
          category: "Western",
          language: "English",
          year: 1953,
          duration: "118 min",
          rating: 7.6,
          videoUrl: "https://www.youtube.com/embed/gJy2wJEP6iw",
          thumbnailUrl: "https://img.youtube.com/vi/gJy2wJEP6iw/maxresdefault.jpg",
          featured: false,
          trending: false,
          status: "published",
          views: 49000,
          likes: 42000
        },
        {
          title: "A Fistful of Dollars (1964)",
          description: "Sergio Leone's Spaghetti Western that made Clint Eastwood a star. Stranger manipulates two warring families. Remake of Yojimbo. Ennio Morricone score. Poncho, cigarillo, squint. Minimalist dialogue. Started the 'Man with No Name' trilogy. Changed Westerns forever.",
          type: "movie",
          category: "Western",
          language: "English",
          year: 1964,
          duration: "99 min",
          rating: 7.9,
          videoUrl: "https://www.youtube.com/embed/TYvDNpLWPs8",
          thumbnailUrl: "https://img.youtube.com/vi/TYvDNpLWPs8/maxresdefault.jpg",
          featured: false,
          trending: true,
          status: "published",
          views: 83000,
          likes: 73000
        },

        // ROMANCE/MUSICAL MOVIES (10 items)
        {
          title: "Casablanca (1942)",
          description: "Michael Curtiz's wartime romance. Humphrey Bogart and Ingrid Bergman reunite in Morocco. 'Here's looking at you, kid.' 'Play it again, Sam.' Rick's Café. Nazi intrigue. Won 3 Oscars including Best Picture. Most quotable film ever. Perfect screenplay.",
          type: "movie",
          category: "Romance",
          language: "English",
          year: 1942,
          duration: "102 min",
          rating: 8.5,
          videoUrl: "https://www.youtube.com/embed/BkL9l7qovsE",
          thumbnailUrl: "https://img.youtube.com/vi/BkL9l7qovsE/maxresdefault.jpg",
          featured: true,
          trending: true,
          status: "published",
          views: 143000,
          likes: 131000
        },
        {
          title: "Singin' in the Rain (1952)",
          description: "Gene Kelly and Stanley Donen's musical masterpiece. Hollywood's transition from silent to sound. Kelly's rain dance is cinema's greatest musical number. Debbie Reynolds, Donald O'Conner ('Make 'Em Laugh'). 'Good morning!' Perfect in every way. AFI's #1 Musical.",
          type: "movie",
          category: "Musical",
          language: "English",
          year: 1952,
          duration: "103 min",
          rating: 8.3,
          videoUrl: "https://www.youtube.com/embed/D1ZYhVpdXbQ",
          thumbnailUrl: "https://img.youtube.com/vi/D1ZYhVpdXbQ/maxresdefault.jpg",
          featured: true,
          trending: true,
          status: "published",
          views: 112000,
          likes: 99000
        },
        {
          title: "West Side Story (1961)",
          description: "Robert Wise and Jerome Robbins' musical Romeo and Juliet in NYC gang warfare. Bernstein score, Sondheim lyrics. 'Tonight,' 'Maria,' 'America.' Natalie Wood, Rita Moreno. Won 10 Oscars including Best Picture. Revolutionary choreography. Shakespeare meets urban grit.",
          type: "movie",
          category: "Musical",
          language: "English",
          year: 1961,
          duration: "152 min",
          rating: 7.6,
          videoUrl: "https://www.youtube.com/embed/bxoC5Oyf_ss",
          thumbnailUrl: "https://img.youtube.com/vi/bxoC5Oyf_ss/maxresdefault.jpg",
          featured: true,
          trending: false,
          status: "published",
          views: 76000,
          likes: 66000
        },
        {
          title: "The Sound of Music (1965)",
          description: "Robert Wise's Rodgers and Hammerstein musical. Julie Andrews as Maria von Trapp. Austrian Alps, nuns, Nazis, seven children. 'Do-Re-Mi,' 'My Favorite Things,' 'Edelweiss.' Won 5 Oscars including Best Picture. Highest-grossing film of 1960s. Pure joy.",
          type: "movie",
          category: "Musical",
          language: "English",
          year: 1965,
          duration: "174 min",
          rating: 8.1,
          videoUrl: "https://www.youtube.com/embed/5YQj4O0DKcE",
          thumbnailUrl: "https://img.youtube.com/vi/5YQj4O0DKcE/maxresdefault.jpg",
          featured: true,
          trending: true,
          status: "published",
          views: 134000,
          likes: 119000
        },
        {
          title: "My Fair Lady (1964)",
          description: "George Cukor's Lerner and Loewe musical. Rex Harrison as Professor Higgins transforming Audrey Hepburn's Eliza Doolittle. Pygmalion story. 'The Rain in Spain,' 'I Could Have Danced All Night.' Won 8 Oscars including Best Picture. Cecil Beaton costumes.",
          type: "movie",
          category: "Musical",
          language: "English",
          year: 1964,
          duration: "170 min",
          rating: 7.8,
          videoUrl: "https://www.youtube.com/embed/c-dLFWrxLGI",
          thumbnailUrl: "https://img.youtube.com/vi/c-dLFWrxLGI/maxresdefault.jpg",
          featured: false,
          trending: false,
          status: "published",
          views: 68000,
          likes: 59000
        },
        {
          title: "Roman Holiday (1953)",
          description: "William Wyler's romantic comedy. Audrey Hepburn (Oscar-winning debut) as princess escaping royal duties in Rome. Gregory Peck as reporter. Vespa ride, Trevi Fountain, Mouth of Truth. Black-and-white Rome never looked better. Bittersweet ending. Pure charm.",
          type: "movie",
          category: "Romance",
          language: "English",
          year: 1953,
          duration: "118 min",
          rating: 8.0,
          videoUrl: "https://www.youtube.com/embed/3WeNfKsFpL0",
          thumbnailUrl: "https://img.youtube.com/vi/3WeNfKsFpL0/maxresdefault.jpg",
          featured: true,
          trending: false,
          status: "published",
          views: 89000,
          likes: 78000
        },
        {
          title: "Breakfast at Tiffany's (1961)",
          description: "Blake Edwards' romantic comedy. Audrey Hepburn as Holly Golightly, party girl in Manhattan. George Peppard. 'Moon River.' Little black dress. Cigarette holder. Cat. Truman Capote novella adaptation. Hepburn's most iconic role. Opens with window shopping.",
          type: "movie",
          category: "Romance",
          language: "English",
          year: 1961,
          duration: "115 min",
          rating: 7.6,
          videoUrl: "https://www.youtube.com/embed/urQVzgEO_w0",
          thumbnailUrl: "https://img.youtube.com/vi/urQVzgEO_w0/maxresdefault.jpg",
          featured: true,
          trending: true,
          status: "published",
          views: 97000,
          likes: 85000
        },
        {
          title: "An Affair to Remember (1957)",
          description: "Leo McCarey's tearjerker. Cary Grant and Deborah Kerr fall in love on cruise, plan to meet atop Empire State Building. Fate intervenes. 'Our Cathedral.' Inspired Sleepless in Seattle. Peak Hollywood romance. Both funny and devastating.",
          type: "movie",
          category: "Romance",
          language: "English",
          year: 1957,
          duration: "115 min",
          rating: 7.4,
          videoUrl: "https://www.youtube.com/embed/VZ9u8S26tGk",
          thumbnailUrl: "https://img.youtube.com/vi/VZ9u8S26tGk/maxresdefault.jpg",
          featured: false,
          trending: false,
          status: "published",
          views: 54000,
          likes: 47000
        },
        {
          title: "The Umbrellas of Cherbourg (1964)",
          description: "Jacques Demy's French musical where all dialogue is sung. Catherine Deneuve and Nino Castelnuovo separated by Algerian War. Michel Legrand score. Vibrant colors. Tragic love story. Not a traditional musical - opera-like. Won Palme d'Or. Gorgeously artificial.",
          type: "movie",
          category: "Musical",
          language: "French",
          year: 1964,
          duration: "91 min",
          rating: 7.8,
          videoUrl: "https://www.youtube.com/embed/K56EKjD0YgM",
          thumbnailUrl: "https://img.youtube.com/vi/K56EKjD0YgM/maxresdefault.jpg",
          featured: false,
          trending: false,
          status: "published",
          views: 41000,
          likes: 35000
        },
        {
          title: "Gigi (1958)",
          description: "Vincente Minnelli's Lerner and Loewe musical. Leslie Caron as Parisian girl trained to be courtesan, falls for Louis Jourdan. Belle Époque France. 'Thank Heaven for Little Girls,' 'I Remember It Well.' Won 9 Oscars including Best Picture. Last great MGM musical.",
          type: "movie",
          category: "Musical",
          language: "English",
          year: 1958,
          duration: "115 min",
          rating: 6.6,
          videoUrl: "https://www.youtube.com/embed/cWKvtdEfzHM",
          thumbnailUrl: "https://img.youtube.com/vi/cWKvtdEfzHM/maxresdefault.jpg",
          featured: false,
          trending: false,
          status: "published",
          views: 38000,
          likes: 31000
        }

      ], insertOptions);
                    
                    console.log('✅ Content seeded: 40 famous movies (1950-1970)');
                } else {
                    console.log(`ℹ️ Content already exists (${contentCount} items) - skipping`);
                }
                
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
                console.log(`\n🎉 Background seed completed in ${elapsed}s`);
                console.log('📊 Summary:');
                console.log('   - Admin: ✓');
                console.log('   - Navigation: 5 items');
                console.log('   - Settings: 4 items');
                console.log(`   - Content: ${contentCount === 0 || force ? '40' : contentCount} items`);
                
            } catch (bgError) {
                console.error('❌ Background seed error:', bgError);
                console.error('Stack:', bgError.stack);
            }
        });
        
    } catch (error) {
        console.error('❌ Seed error:', error);
        
        let errorMessage = error.message;
        let statusCode = 500;
        
        if (error.message.includes('timeout') || error.message.includes('buffering')) {
            statusCode = 503;
            errorMessage = 'Database connection timeout. Check your MongoDB connection.';
        } else if (error.message.includes('ENOTFOUND') || error.message.includes('ECONNREFUSED')) {
            statusCode = 503;
            errorMessage = 'Cannot reach MongoDB server. Check MONGO_URI and network.';
        }
        
        res.status(statusCode).json({ 
            error: errorMessage,
            details: error.message
        });
    }
});

// Seed status check endpoint
app.get('/api/seed/status', async (req, res) => {
    try {
        const stats = {
            admins: await Admin.countDocuments(),
            navigation: await Navigation.countDocuments(),
            settings: await Settings.countDocuments(),
            content: await Content.countDocuments()
        };
        
        const isComplete = stats.admins > 0 && stats.navigation > 0 && 
                          stats.settings > 0 && stats.content > 0;
        
        res.json({
            status: isComplete ? 'complete' : 'incomplete',
            counts: stats,
            expected: {
                admins: 1,
                navigation: 5,
                settings: 4,
                content: 40
            },
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// 404 HANDLER
// ========================================

app.use((req, res) => {
    res.status(404).json({ 
        error: 'Route not found',
        path: req.path,
        message: 'This endpoint does not exist'
    });
});

// ========================================
// ERROR HANDLER
// ========================================

app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ 
        error: 'Internal server error',
        message: err.message 
    });
});

// ========================================
// START SERVER
// Works on both Railway (traditional) and Vercel (serverless)
// ========================================

// module.exports MUST come before app.listen for Vercel
module.exports = app;

// Only start listening when NOT on Vercel
if (process.env.VERCEL !== '1') {
    const server = app.listen(PORT, '0.0.0.0', () => {
        console.log('='.repeat(50));
        console.log('✅ SERVER STARTED SUCCESSFULLY!');
        console.log(`🚀 Listening on http://0.0.0.0:${PORT}`);
        console.log(`📍 Admin Login: http://0.0.0.0:${PORT}/api/admin/login`);
        console.log(`📍 Content:     http://0.0.0.0:${PORT}/api/content`);
        console.log(`📍 Seed:        http://0.0.0.0:${PORT}/api/seed`);
        console.log('='.repeat(50));
    });

    server.on('error', (error) => {
        console.error('❌ Server error:', error);
        if (error.code === 'EADDRINUSE') {
            console.error(`Port ${PORT} is already in use`);
            process.exit(1);
        }
    });

    process.on('SIGTERM', () => {
        server.close(() => {
            mongoose.connection.close(false, () => process.exit(0));
        });
    });
}
