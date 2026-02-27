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

const MONGOTESTDB_URI = process.env.MONGO_URI;
 
const JWT_SECRET = process.env.JWT_SECRET || 'default-secret-change-me';

console.log('🔧 MongoDB URI:', MONGOTESTDB_URI ? '✓ Set' : '✗ Missing');
console.log('🔧 JWT Secret:', JWT_SECRET ? '✓ Set' : '✗ Missing');

// ========================================
// MONGODB CONNECTION
// ========================================

if (MONGOTESTDB_URI) {
    console.log('🔄 Connecting to MongoDB...');
    mongoose.connect(MONGOTESTDB_URI)
        .then(() => {
            console.log('✅ MongoDB Connected');
            console.log('📊 Database:', mongoose.connection.name);
        })
        .catch((error) => {
            console.error('❌ MongoDB Error:', error.message);
            // Don't exit - let server start anyway
        });
} else {
    console.warn('⚠️  No MongoDB URI - running without database');
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

app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        port: PORT
    });
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
        console.log('🔧 MongoDB URI:', MONGOTESTDB_URI ? '✓ Set' : '✗ Missing');

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
            console.log('✅ Admin created  (user: admin / pass: admin123)');
        }

        // ── Navigation ─────────────────────────────────────────
        await Navigation.deleteMany({});
        await Navigation.insertMany([
            { label: 'Home',          url: '/',             icon: '🏠', order: 0, active: true },
            { label: 'Movies',        url: '/movies',        icon: '🎬', order: 1, active: true },
            { label: 'Series',        url: '/series',        icon: '📺', order: 2, active: true },
            { label: 'Documentaries', url: '/documentaries', icon: '📽️', order: 3, active: true },
            { label: 'Live',          url: '/live',          icon: '🔴', order: 4, active: true }
        ]);
        console.log('✅ Navigation created (5 items)');

        // ── Settings ───────────────────────────────────────────
        await Settings.deleteMany({});
        await Settings.insertMany([
            { key: 'site_name',       value: 'ClassicFlims',           category: 'general' },
            { key: 'site_tagline',    value: 'PREMIUM CLASSIC CINEMA',  category: 'general' },
            { key: 'primary_color',   value: '#ff3366',                 category: 'theme'   },
            { key: 'secondary_color', value: '#7c3aed',                 category: 'theme'   }
        ]);
        console.log('✅ Settings created (4 items)');

        // ── Content (40 items — only if DB is empty) ───────────
        const contentCount = await Content.countDocuments();
        const force = req.query.force === 'true';

    if (contentCount === 0 || force) {
      if (force && contentCount > 0) {
        console.log('⚠️ Force mode: Deleting existing content...');
        await Content.deleteMany({});
      }
            console.log('🔧 MongoDB URI:', MONGOTESTDB_URI ? '✓ Set' : '✗ Missing');
            console.log('🔧 JWT Secret:', JWT_SECRET ? '✓ Set' : '✗ Missing');
            console.log('\n📌 Seeding Content (70 items)...');
      await Content.insertMany([

     // ==============================
        // MOVIES — 10 Classic Hindi Films (1950–1970) on YouTube
        // ==============================
        {
          title: 'Awaara (1951)',
          description: 'Raj Kapoors landmark film about a vagabond who questions whether crime is destiny or environment. Nargis as his childhood sweetheart. The song Awaara Hoon became a global phenomenon, especially in the Soviet Union and China. A cornerstone of world cinema.',
          type: 'movie',
          category: 'Classic Hindi Drama',
          language: 'Hindi',
          year: 1951,
          duration: '193 min',
          rating: 8.2,
          videoUrl: 'https://www.youtube.com/embed/7k2H6YLGDLQ',
          thumbnailUrl: 'https://img.youtube.com/vi/7k2H6YLGDLQ/hqdefault.jpg',
          featured: true,
          trending: true,
          status: 'published',
          views: 62000,
          likes: 54000
        },
        {
          title: 'Pyaasa (1957)',
          description: 'Guru Dutts poetic masterpiece about a struggling poet rejected by society. Often ranked among the greatest films ever made. Waheeda Rehman, Mala Sinha and Guru Dutt create magic with SD Burmans soulful music. A scathing critique of materialism and hypocrisy.',
          type: 'movie',
          category: 'Classic Hindi',
          language: 'Hindi',
          year: 1957,
          duration: '146 min',
          rating: 8.4,
          videoUrl: 'https://www.youtube.com/embed/KVFpSMJVhRo',
          thumbnailUrl: 'https://img.youtube.com/vi/KVFpSMJVhRo/hqdefault.jpg',
          featured: true,
          trending: true,
          status: 'published',
          views: 51000,
          likes: 44000
        },
        {
          title: 'Mughal-e-Azam (1960)',
          description: 'K. Asifs legendary magnum opus — Prince Salims forbidden love for court dancer Anarkali. Dilip Kumar, Madhubala and Prithviraj Kapoor in iconic roles. Naushads music is immortal. Took 16 years to make. The pinnacle of Hindi cinemas golden age.',
          type: 'movie',
          category: 'Classic Hindi Epic',
          language: 'Hindi',
          year: 1960,
          duration: '197 min',
          rating: 8.7,
          videoUrl: 'https://www.youtube.com/embed/4JpxmWn4Uxg',
          thumbnailUrl: 'https://img.youtube.com/vi/4JpxmWn4Uxg/hqdefault.jpg',
          featured: true,
          trending: true,
          status: 'published',
          views: 72000,
          likes: 63000
        },
        {
          title: 'Mother India (1957)',
          description: 'Mehboob Khans epic saga of a poor womans struggle to raise her sons and protect her land. Nargis in a towering performance. Indias first submission for the Oscars Best Foreign Film. A defining film of Indian independence and motherhood.',
          type: 'movie',
          category: 'Classic Hindi Epic',
          language: 'Hindi',
          year: 1957,
          duration: '172 min',
          rating: 8.1,
          videoUrl: 'https://www.youtube.com/embed/0ZWIrBQpDjY',
          thumbnailUrl: 'https://img.youtube.com/vi/0ZWIrBQpDjY/hqdefault.jpg',
          featured: true,
          trending: true,
          status: 'published',
          views: 48000,
          likes: 41000
        },
        {
          title: 'Kaagaz Ke Phool (1959)',
          description: 'Guru Dutts tragic masterpiece about a film directors rise and fall — Indias first CinemaScope film. A commercial failure on release, now recognized as one of the greatest Indian films ever made. VK Murthys stunning black-and-white cinematography.',
          type: 'movie',
          category: 'Classic Hindi Drama',
          language: 'Hindi',
          year: 1959,
          duration: '148 min',
          rating: 8.2,
          videoUrl: 'https://www.youtube.com/embed/wDr4_1-HQWM',
          thumbnailUrl: 'https://img.youtube.com/vi/wDr4_1-HQWM/hqdefault.jpg',
          featured: true,
          trending: false,
          status: 'published',
          views: 35000,
          likes: 30000
        },
        {
          title: 'Devdas (1955)',
          description: 'Bimal Roys definitive adaptation of Sarat Chandras tragic romance. Dilip Kumar as the self-destructive lover, Suchitra Sen as Paro, Vyjayantimala as Chandramukhi. SD Burmans melancholic music perfectly captures doomed love.',
          type: 'movie',
          category: 'Classic Hindi Romance',
          language: 'Hindi',
          year: 1955,
          duration: '159 min',
          rating: 7.9,
          videoUrl: 'https://www.youtube.com/embed/QUkh7pVBddk',
          thumbnailUrl: 'https://img.youtube.com/vi/QUkh7pVBddk/hqdefault.jpg',
          featured: true,
          trending: false,
          status: 'published',
          views: 30000,
          likes: 26000
        },
        {
          title: 'Madhumati (1958)',
          description: 'Bimal Roys supernatural romantic thriller — a man revisits a haunted mansion and remembers a past life. Dilip Kumar and Vyjayantimala in a reincarnation tale with Salil Chowdhurys haunting music. Won 9 Filmfare Awards.',
          type: 'movie',
          category: 'Classic Hindi',
          language: 'Hindi',
          year: 1958,
          duration: '175 min',
          rating: 7.9,
          videoUrl: 'https://www.youtube.com/embed/q7xfxq1ARIY',
          thumbnailUrl: 'https://img.youtube.com/vi/q7xfxq1ARIY/hqdefault.jpg',
          featured: false,
          trending: true,
          status: 'published',
          views: 27000,
          likes: 22000
        },
        {
          title: 'Baiju Bawra (1952)',
          description: 'Vijay Bhatts legendary musical masterpiece about a musician who challenges Tansen at Emperor Akbars court. Featuring immortal classical music by Naushad. Bharat Bhushan and Meena Kumari deliver career-defining performances. Won the first-ever Filmfare Best Film.',
          type: 'movie',
          category: 'Classic Hindi Musical',
          language: 'Hindi',
          year: 1952,
          duration: '155 min',
          rating: 8.0,
          videoUrl: 'https://www.youtube.com/embed/s9cO4PcCKvs',
          thumbnailUrl: 'https://img.youtube.com/vi/s9cO4PcCKvs/hqdefault.jpg',
          featured: true,
          trending: false,
          status: 'published',
          views: 34000,
          likes: 28000
        },
        {
          title: 'Naya Daur (1957)',
          description: 'BR Chopras social drama about modernization vs tradition. A tonga driver races a bus to prove human will can triumph over machines. Dilip Kumar and Vyjayantimala lead a spirited ensemble. OP Nayyars rousing music captures rural Indias pride.',
          type: 'movie',
          category: 'Classic Hindi Social',
          language: 'Hindi',
          year: 1957,
          duration: '173 min',
          rating: 7.8,
          videoUrl: 'https://www.youtube.com/embed/IREjC3Zfcio',
          thumbnailUrl: 'https://img.youtube.com/vi/IREjC3Zfcio/hqdefault.jpg',
          featured: false,
          trending: true,
          status: 'published',
          views: 22000,
          likes: 18000
        },
        {
          title: 'Sahib Bibi Aur Ghulam (1962)',
          description: 'A decaying feudal mansion, a lonely wife, and a young servant. Meena Kumaris heartbreaking performance as an alcoholic aristocratic wife. Guru Dutt produced this masterpiece. A meditation on the death of zamindari culture.',
          type: 'movie',
          category: 'Classic Hindi Drama',
          language: 'Hindi',
          year: 1962,
          duration: '152 min',
          rating: 8.2,
          videoUrl: 'https://www.youtube.com/embed/bD9KCcAHCaI',
          thumbnailUrl: 'https://img.youtube.com/vi/bD9KCcAHCaI/hqdefault.jpg',
          featured: true,
          trending: false,
          status: 'published',
          views: 25000,
          likes: 21000
        },

        // ==============================
        // SERIES — 10 Classic Indian TV Series (1950s–1970s era content on YouTube)
        // ==============================
        {
          title: 'Ramayana (1987) — Episode 1',
          description: 'Ramanand Sagars iconic Doordarshan serial. Episode 1: The story begins in Ayodhya with King Dasharatha and the birth of Lord Rama. Holds the Guinness World Record for most-watched TV show. Arun Govil as Rama, Deepika Chikhalia as Sita.',
          type: 'series',
          category: 'Mythological',
          language: 'Hindi',
          year: 1987,
          duration: '45 min/ep',
          rating: 9.2,
          videoUrl: 'https://www.youtube.com/embed/QFfpfMGcJBY',
          thumbnailUrl: 'https://img.youtube.com/vi/QFfpfMGcJBY/hqdefault.jpg',
          featured: true,
          trending: true,
          status: 'published',
          views: 89000,
          likes: 78000
        },
        {
          title: 'Mahabharat (1988) — Episode 1',
          description: 'B.R. Chopras magnum opus. Episode 1 introduces the Kuru dynasty. With Mukesh Khanna as Bhishma and Nitish Bharadwaj as Krishna. 94 episodes that captivated a billion viewers every Sunday morning.',
          type: 'series',
          category: 'Mythological',
          language: 'Hindi',
          year: 1988,
          duration: '45 min/ep',
          rating: 9.1,
          videoUrl: 'https://www.youtube.com/embed/5VYrbNEQDGo',
          thumbnailUrl: 'https://img.youtube.com/vi/5VYrbNEQDGo/hqdefault.jpg',
          featured: true,
          trending: true,
          status: 'published',
          views: 76000,
          likes: 67000
        },
        {
          title: 'Malgudi Days (1987) — Season 1',
          description: 'Shankar Nags timeless adaptation of R.K. Narayans stories of the fictional South Indian town of Malgudi. Young Swamis charming adventures. The nostalgic theme by L. Subramaniam is forever etched in memory.',
          type: 'series',
          category: 'Family Drama',
          language: 'Hindi',
          year: 1987,
          duration: '25 min/ep',
          rating: 9.0,
          videoUrl: 'https://www.youtube.com/embed/q1kZeOkYFXA',
          thumbnailUrl: 'https://img.youtube.com/vi/q1kZeOkYFXA/hqdefault.jpg',
          featured: true,
          trending: false,
          status: 'published',
          views: 41000,
          likes: 36500
        },
        {
          title: 'Byomkesh Bakshi (1993) — Season 1',
          description: 'Doordarshans beloved detective series. Rajit Kapur plays the truth-seeker Byomkesh Bakshi in complex mysteries set in 1940s Kolkata. Acclaimed for its authentic period atmosphere and intelligent writing.',
          type: 'series',
          category: 'Mystery Drama',
          language: 'Hindi',
          year: 1993,
          duration: '50 min/ep',
          rating: 8.7,
          videoUrl: 'https://www.youtube.com/embed/Gvp6ULuOx14',
          thumbnailUrl: 'https://img.youtube.com/vi/Gvp6ULuOx14/hqdefault.jpg',
          featured: false,
          trending: true,
          status: 'published',
          views: 34000,
          likes: 28500
        },
        {
          title: 'Buniyaad (1986)',
          description: 'Indias most celebrated family saga — the Haveli Ram family from Partition 1947 to the 1980s. Directed by Ramesh Sippy, written by Manohar Shyam Joshi. The first major prime-time serial on Doordarshan.',
          type: 'series',
          category: 'Family Saga',
          language: 'Hindi',
          year: 1986,
          duration: '50 min/ep',
          rating: 8.8,
          videoUrl: 'https://www.youtube.com/embed/YkDsIjBRMYo',
          thumbnailUrl: 'https://img.youtube.com/vi/YkDsIjBRMYo/hqdefault.jpg',
          featured: true,
          trending: false,
          status: 'published',
          views: 31000,
          likes: 26000
        },
        {
          title: 'Hum Log (1984)',
          description: 'Indias first soap opera — the Rastogi familys everyday struggles. 156 episodes, 50 million viewers per episode. Changed the landscape of Indian television forever. Ashok Kumar as the narrator.',
          type: 'series',
          category: 'Social Drama',
          language: 'Hindi',
          year: 1984,
          duration: '23 min/ep',
          rating: 8.3,
          videoUrl: 'https://www.youtube.com/embed/LYjjrLRFLFE',
          thumbnailUrl: 'https://img.youtube.com/vi/LYjjrLRFLFE/hqdefault.jpg',
          featured: false,
          trending: false,
          status: 'published',
          views: 18000,
          likes: 14500
        },
        {
          title: 'Vikram Aur Betaal (1985)',
          description: 'King Vikramaditya carries a corpse possessed by the spirit Betaal, who poses a riddle each episode. A beloved Doordarshan mythological-folk series that mesmerised a generation.',
          type: 'series',
          category: 'Mythology Folk',
          language: 'Hindi',
          year: 1985,
          duration: '25 min/ep',
          rating: 8.5,
          videoUrl: 'https://www.youtube.com/embed/DNWKpGGxfIk',
          thumbnailUrl: 'https://img.youtube.com/vi/DNWKpGGxfIk/hqdefault.jpg',
          featured: false,
          trending: true,
          status: 'published',
          views: 27000,
          likes: 22000
        },
        {
          title: 'Circus (1989)',
          description: 'Shah Rukh Khans television debut — a young trainee at a traveling circus discovers friendships and dreams. Directed by Aziz Mirza. The launchpad for the King of Bollywood.',
          type: 'series',
          category: 'Drama',
          language: 'Hindi',
          year: 1989,
          duration: '45 min/ep',
          rating: 8.4,
          videoUrl: 'https://www.youtube.com/embed/Fxg1F1WGXU4',
          thumbnailUrl: 'https://img.youtube.com/vi/Fxg1F1WGXU4/hqdefault.jpg',
          featured: true,
          trending: true,
          status: 'published',
          views: 44000,
          likes: 38000
        },
        {
          title: 'Nukkad (1986)',
          description: 'Ensemble drama about everyday lives of people at a Delhi street corner. Two seasons of raw honesty, humor and empathy. One of Doordarshans most beloved series. Kundan Shah and Saeed Mirzas masterpiece of realist television.',
          type: 'series',
          category: 'Social Drama',
          language: 'Hindi',
          year: 1986,
          duration: '25 min/ep',
          rating: 8.6,
          videoUrl: 'https://www.youtube.com/embed/dQqr5TMKP0U',
          thumbnailUrl: 'https://img.youtube.com/vi/dQqr5TMKP0U/hqdefault.jpg',
          featured: false,
          trending: false,
          status: 'published',
          views: 19500,
          likes: 16200
        },
        {
          title: 'Tenali Rama (1988)',
          description: 'The witty tales of Tenali Rama, court jester of Emperor Krishnadevaraya. Each episode showcases clever solutions to impossible problems. A beloved Tamil/Telugu DD series that taught life lessons through humor.',
          type: 'series',
          category: 'Historical Comedy',
          language: 'Tamil',
          year: 1988,
          duration: '25 min/ep',
          rating: 8.1,
          videoUrl: 'https://www.youtube.com/embed/T7M2tBqRZrs',
          thumbnailUrl: 'https://img.youtube.com/vi/T7M2tBqRZrs/hqdefault.jpg',
          featured: false,
          trending: true,
          status: 'published',
          views: 23000,
          likes: 19000
        },

        // ==============================
        // DOCUMENTARIES — 10 Famous 1950–1970 era (YouTube)
        // ==============================
        {
          title: 'Night and Fog (1956)',
          description: 'Alain Resnais haunting documentary about Nazi concentration camps — alternating colour present-day footage with black-and-white archival film. One of the most powerful anti-war films ever made. A defining work of documentary cinema.',
          type: 'documentary',
          category: 'War History',
          language: 'French',
          year: 1956,
          duration: '32 min',
          rating: 8.6,
          videoUrl: 'https://www.youtube.com/embed/6sJjUN6QiI4',
          thumbnailUrl: 'https://img.youtube.com/vi/6sJjUN6QiI4/hqdefault.jpg',
          featured: true,
          trending: false,
          status: 'published',
          views: 22000,
          likes: 18500
        },
        {
          title: 'Salesman (1969)',
          description: 'The Maysles brothers portrait of four Bible salesmen traversing America. A landmark of cinema verite and direct cinema. Profound and poignant look at the American Dream and its discontents.',
          type: 'documentary',
          category: 'Social',
          language: 'English',
          year: 1969,
          duration: '85 min',
          rating: 8.0,
          videoUrl: 'https://www.youtube.com/embed/6IXzP8aZnQs',
          thumbnailUrl: 'https://img.youtube.com/vi/6IXzP8aZnQs/hqdefault.jpg',
          featured: true,
          trending: false,
          status: 'published',
          views: 17000,
          likes: 14000
        },
        {
          title: 'Primary (1960)',
          description: 'Robert Drews pioneering direct cinema documentary following John F. Kennedy and Hubert Humphrey in the 1960 Wisconsin primary. The film that invented modern political documentary filmmaking.',
          type: 'documentary',
          category: 'Political History',
          language: 'English',
          year: 1960,
          duration: '60 min',
          rating: 7.9,
          videoUrl: 'https://www.youtube.com/embed/N3i6PYQXQYM',
          thumbnailUrl: 'https://img.youtube.com/vi/N3i6PYQXQYM/hqdefault.jpg',
          featured: false,
          trending: true,
          status: 'published',
          views: 14000,
          likes: 11000
        },
        {
          title: 'Chronique dun Ete (1961)',
          description: 'Jean Rouch and Edgar Morins Summer Chronicle — Parisians asked Are you happy? A foundational work of cinema verite. Honest, experimental, and groundbreaking in documentary form.',
          type: 'documentary',
          category: 'Social History',
          language: 'French',
          year: 1961,
          duration: '85 min',
          rating: 7.8,
          videoUrl: 'https://www.youtube.com/embed/2k68I0T_rFw',
          thumbnailUrl: 'https://img.youtube.com/vi/2k68I0T_rFw/hqdefault.jpg',
          featured: false,
          trending: false,
          status: 'published',
          views: 11000,
          likes: 8500
        },
        {
          title: 'Le Joli Mai (1963)',
          description: 'Chris Marker captures Paris in May 1962 — interviews with ordinary Parisians about hope, politics, and life after the Algerian War. A defining masterpiece of French documentary cinema.',
          type: 'documentary',
          category: 'Social History',
          language: 'French',
          year: 1963,
          duration: '165 min',
          rating: 8.1,
          videoUrl: 'https://www.youtube.com/embed/z45lqfJ57FA',
          thumbnailUrl: 'https://img.youtube.com/vi/z45lqfJ57FA/hqdefault.jpg',
          featured: false,
          trending: false,
          status: 'published',
          views: 9000,
          likes: 7200
        },
        {
          title: 'Woodstock (1970)',
          description: 'Michael Wadleighs definitive three-hour record of the legendary 1969 Woodstock music festival. Featuring Jimi Hendrix, Janis Joplin, The Who and many more. Won the Academy Award for Best Documentary Feature.',
          type: 'documentary',
          category: 'Music History',
          language: 'English',
          year: 1970,
          duration: '184 min',
          rating: 8.2,
          videoUrl: 'https://www.youtube.com/embed/yMVsSwHHyFg',
          thumbnailUrl: 'https://img.youtube.com/vi/yMVsSwHHyFg/hqdefault.jpg',
          featured: true,
          trending: true,
          status: 'published',
          views: 38000,
          likes: 32000
        },
        {
          title: 'Dont Look Back (1967)',
          description: 'D.A. Pennebakers seminal portrait of Bob Dylan on his 1965 UK tour. Cinema verite at its finest. Dylan is magnetic — confrontational, poetic, brilliantly evasive. One of the greatest music documentaries ever made.',
          type: 'documentary',
          category: 'Music History',
          language: 'English',
          year: 1967,
          duration: '96 min',
          rating: 8.1,
          videoUrl: 'https://www.youtube.com/embed/rNHVk6-Gjnw',
          thumbnailUrl: 'https://img.youtube.com/vi/rNHVk6-Gjnw/hqdefault.jpg',
          featured: true,
          trending: true,
          status: 'published',
          views: 29000,
          likes: 24000
        },
        {
          title: 'Le Sang des Betes (1949)',
          description: 'Georges Franjus stark portrait of a Paris slaughterhouse — juxtaposing placid suburban life with industrial death. A controversial and visceral masterpiece of French documentary. Essential viewing for understanding postwar European cinema.',
          type: 'documentary',
          category: 'Art Film',
          language: 'French',
          year: 1949,
          duration: '22 min',
          rating: 7.7,
          videoUrl: 'https://www.youtube.com/embed/KZWiJ0TLHCU',
          thumbnailUrl: 'https://img.youtube.com/vi/KZWiJ0TLHCU/hqdefault.jpg',
          featured: false,
          trending: false,
          status: 'published',
          views: 7500,
          likes: 5800
        },
        {
          title: 'India — Matri Bhumi (1959)',
          description: 'Roberto Rossellinis portrait of India — its sacred rivers, ancient temples, cities, and village life. Shot with a documentary eye by the father of Italian neorealism. A rare Western gaze on 1950s India with genuine respect and curiosity.',
          type: 'documentary',
          category: 'Historical Travel',
          language: 'Italian/Hindi',
          year: 1959,
          duration: '90 min',
          rating: 7.8,
          videoUrl: 'https://www.youtube.com/embed/3i3ZLvLJjNk',
          thumbnailUrl: 'https://img.youtube.com/vi/3i3ZLvLJjNk/hqdefault.jpg',
          featured: false,
          trending: false,
          status: 'published',
          views: 12000,
          likes: 9500
        },
        {
          title: 'A Time for Burning (1966)',
          description: 'An American documentary about a white Lutheran minister attempting to integrate his congregation in Omaha, Nebraska. Raw, honest and compelling. Won the Directors Guild Award. A landmark of American social documentary.',
          type: 'documentary',
          category: 'Social History',
          language: 'English',
          year: 1966,
          duration: '58 min',
          rating: 7.9,
          videoUrl: 'https://www.youtube.com/embed/2lYyPKhGEo8',
          thumbnailUrl: 'https://img.youtube.com/vi/2lYyPKhGEo8/hqdefault.jpg',
          featured: false,
          trending: false,
          status: 'published',
          views: 8000,
          likes: 6200
        },

        // ==============================
        // LIVE — 10 Classic Performances (1950–1970) on YouTube
        // ==============================
        {
          title: 'Ravi Shankar — Monterey Pop Festival (1967)',
          description: 'Pandit Ravi Shankars historic sitar performance at Monterey that introduced Indian classical music to Western rock audiences. A transcendent raga that moved the crowd to silence and meditation. The moment the world fell in love with Indian music.',
          type: 'live',
          category: 'Classical Music',
          language: 'Instrumental',
          year: 1967,
          duration: '15 min',
          rating: 9.3,
          videoUrl: 'https://www.youtube.com/embed/eSAFg_Lk7cY',
          thumbnailUrl: 'https://img.youtube.com/vi/eSAFg_Lk7cY/hqdefault.jpg',
          featured: true,
          trending: true,
          status: 'published',
          views: 48000,
          likes: 43000
        },
        {
          title: 'M.S. Subbulakshmi — UN General Assembly (1966)',
          description: 'M.S. Subbulakshmis historic performance at the United Nations General Assembly in 1966 — the first Indian musician to be invited to perform there. Her rendition of Maitreem Bhajata is transcendent. A moment of cultural history.',
          type: 'live',
          category: 'Carnatic Vocal',
          language: 'Sanskrit',
          year: 1966,
          duration: '30 min',
          rating: 9.4,
          videoUrl: 'https://www.youtube.com/embed/wkFgq7HGXqo',
          thumbnailUrl: 'https://img.youtube.com/vi/wkFgq7HGXqo/hqdefault.jpg',
          featured: true,
          trending: true,
          status: 'published',
          views: 52000,
          likes: 47000
        },
        {
          title: 'Bismillah Khan — Raag Bhairavi (1955)',
          description: 'Ustad Bismillah Khan performing Raag Bhairavi on the shehnai — one of the earliest recorded live performances of the maestro. The Bharat Ratna awardee who never left Varanasi. Pure devotional classical music from another era.',
          type: 'live',
          category: 'Hindustani Instrumental',
          language: 'Instrumental',
          year: 1955,
          duration: '22 min',
          rating: 9.1,
          videoUrl: 'https://www.youtube.com/embed/g_GGl1JliN8',
          thumbnailUrl: 'https://img.youtube.com/vi/g_GGl1JliN8/hqdefault.jpg',
          featured: true,
          trending: false,
          status: 'published',
          views: 28000,
          likes: 24000
        },
        {
          title: 'Ali Akbar Khan — Sarod Recital (1955)',
          description: 'Ustad Ali Akbar Khans celebrated sarod recital — one of the first Indian classical recordings released in America. Disciple of Baba Allauddin Khan and brother-in-law of Ravi Shankar. A monumental recording in world music history.',
          type: 'live',
          category: 'Hindustani Instrumental',
          language: 'Instrumental',
          year: 1955,
          duration: '52 min',
          rating: 9.0,
          videoUrl: 'https://www.youtube.com/embed/3yHBq_LlvRA',
          thumbnailUrl: 'https://img.youtube.com/vi/3yHBq_LlvRA/hqdefault.jpg',
          featured: false,
          trending: false,
          status: 'published',
          views: 14200,
          likes: 12500
        },
        {
          title: 'Lata Mangeshkar — Live Concert Kolkata (1969)',
          description: 'Lata Mangeshkars rare live concert footage from Kolkata in 1969. The Nightingale of India at her peak — Lag Ja Gale, Tere Bina Zindagi Se and other immortal songs performed live before an enthralled audience.',
          type: 'live',
          category: 'Bollywood Music',
          language: 'Hindi',
          year: 1969,
          duration: '65 min',
          rating: 9.2,
          videoUrl: 'https://www.youtube.com/embed/3T_LdQm-U0E',
          thumbnailUrl: 'https://img.youtube.com/vi/3T_LdQm-U0E/hqdefault.jpg',
          featured: true,
          trending: true,
          status: 'published',
          views: 41000,
          likes: 36500
        },
        {
          title: 'Kishore Kumar — Live Performance (1969)',
          description: 'A rare live stage performance of Kishore Kumar in 1969 — his trademark yodelling, mimicry and melodious voice captivate the audience. Songs from his classic films including Padosan and Chalti Ka Naam Gaadi.',
          type: 'live',
          category: 'Bollywood Music',
          language: 'Hindi',
          year: 1969,
          duration: '55 min',
          rating: 9.0,
          videoUrl: 'https://www.youtube.com/embed/nLRJR_UfhLs',
          thumbnailUrl: 'https://img.youtube.com/vi/nLRJR_UfhLs/hqdefault.jpg',
          featured: false,
          trending: true,
          status: 'published',
          views: 35000,
          likes: 31000
        },
        {
          title: 'Mohammed Rafi — Golden Jubilee Concert (1968)',
          description: 'Mohammed Rafis golden jubilee concert — live renditions of his most beloved songs including Chaudhvin Ka Chand, Baharon Phool Barsao and Abhi Na Jao Chhod Kar. The voice of a golden era of Hindi film music.',
          type: 'live',
          category: 'Bollywood Music',
          language: 'Hindi',
          year: 1968,
          duration: '70 min',
          rating: 9.2,
          videoUrl: 'https://www.youtube.com/embed/8k9wHoTkoxY',
          thumbnailUrl: 'https://img.youtube.com/vi/8k9wHoTkoxY/hqdefault.jpg',
          featured: true,
          trending: true,
          status: 'published',
          views: 54000,
          likes: 49000
        },
        {
          title: 'Pandit Bhimsen Joshi — Raag Miyan Ki Malhar (1967)',
          description: 'Pandit Bhimsen Joshi performing the majestic Raag Miyan Ki Malhar in 1967. The definitive voice of the Kirana Gharana. His khyal vocals are transcendent — this rare recording captures the maestro at his absolute finest.',
          type: 'live',
          category: 'Hindustani Vocal',
          language: 'Hindi/Sanskrit',
          year: 1967,
          duration: '48 min',
          rating: 9.3,
          videoUrl: 'https://www.youtube.com/embed/7FDfA_CZFvM',
          thumbnailUrl: 'https://img.youtube.com/vi/7FDfA_CZFvM/hqdefault.jpg',
          featured: true,
          trending: false,
          status: 'published',
          views: 17500,
          likes: 15000
        },
        {
          title: 'T.N. Rajarathnam Pillai — Nadaswaram (1965)',
          description: 'T.N. Rajarathnam Pillai performing the nadaswaram — the iconic South Indian temple wind instrument. One of the finest recordings of this rare instrument, captured live at a classical sabha in Chennai in 1965.',
          type: 'live',
          category: 'Carnatic Instrumental',
          language: 'Instrumental',
          year: 1965,
          duration: '42 min',
          rating: 8.5,
          videoUrl: 'https://www.youtube.com/embed/ZJY9Q3M9n0w',
          thumbnailUrl: 'https://img.youtube.com/vi/ZJY9Q3M9n0w/hqdefault.jpg',
          featured: false,
          trending: false,
          status: 'published',
          views: 9500,
          likes: 8000
        },
        {
          title: 'Girija Devi — Thumri at Benares (1968)',
          description: 'Padma Vibhushan Girija Devi, Queen of Thumri, performing in Varanasi in 1968. A rare live recording of thumri, dadra and kajri — devotion, romance and playfulness at their finest. An irreplaceable document of the Banaras gharana tradition.',
          type: 'live',
          category: 'Hindustani Semi-classical',
          language: 'Bhojpuri/Hindi',
          year: 1968,
          duration: '65 min',
          rating: 8.8,
          videoUrl: 'https://www.youtube.com/embed/AQSP7l6QQQA',
          thumbnailUrl: 'https://img.youtube.com/vi/AQSP7l6QQQA/hqdefault.jpg',
          featured: false,
          trending: false,
          status: 'published',
          views: 12000,
          likes: 10200
        }

      ]); // end Content.insertMany
            console.log('✅ Content created: 40 items (10 movies + 10 series + 10 documentaries + 10 live)');
        } else {
            console.log(`ℹ️  Content already exists (${contentCount} items) — skipping content seed`);
        }

        res.json({
            message: '✅ Database seeded successfully!',
            summary: {
                admins:     'admin / admin123',
                navigation: 5,
                settings:   4,
                content:    '40 items — 10 movies, 10 series, 10 documentaries, 10 live'
            }
        });
    } catch (error) {
        console.error('❌ Seed error:', error);
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
