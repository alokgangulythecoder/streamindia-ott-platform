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

                // ================================================
                // MOVIES — Indian public-domain on archive.org
                // ================================================
    {
    "title": "Baiju Bawra (1952)",
    "description": "Vijay Bhatt's legendary musical masterpiece about a musician who challenges Tansen at Emperor Akbar's court. Featuring immortal classical music by Naushad. Bharat Bhushan and Meena Kumari deliver career-defining performances. The film won the first-ever Filmfare Award for Best Film.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1952,
    "duration": "155 min",
    "rating": 8,
    "videoUrl": "https://archive.org/embed/BaijuBawra1952",
    "thumbnailUrl": "https://archive.org/services/img/BaijuBawra1952",
    "featured": true,
    "trending": true,
    "status": "published",
    "views": 34000,
    "likes": 28500
  },
  {
    "title": "Pyaasa (1957)",
    "description": "Guru Dutt's poetic masterpiece about a struggling poet rejected by society. Often ranked among the greatest films ever made. Waheeda Rehman, Mala Sinha and Guru Dutt create magic with SD Burman's soulful music. A scathing critique of materialism and hypocrisy.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1957,
    "duration": "146 min",
    "rating": 8.4,
    "videoUrl": "https://archive.org/embed/pyaasa-1957-guru-dutt-classic-hindi-film",
    "thumbnailUrl": "https://archive.org/services/img/pyaasa-1957-guru-dutt-classic-hindi-film",
    "featured": true,
    "trending": true,
    "status": "published",
    "views": 41000,
    "likes": 36500
  },
  {
    "title": "Madhumati (1958)",
    "description": "Bimal Roy's supernatural romantic thriller — a man revisits a haunted mansion and remembers a past life. Dilip Kumar and Vyjayantimala in a reincarnation tale with Salil Chowdhury's haunting music. Holds the record of 9 Filmfare Awards.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1958,
    "duration": "175 min",
    "rating": 7.9,
    "videoUrl": "https://archive.org/embed/madhumati-1958-bimal-roy-classic-hindi-film",
    "thumbnailUrl": "https://archive.org/services/img/madhumati-1958-bimal-roy-classic-hindi-film",
    "featured": true,
    "trending": false,
    "status": "published",
    "views": 28000,
    "likes": 23500
  },
  {
    "title": "Anari (1959)",
    "description": "Hrishikesh Mukherjee's directorial debut — Raj Kapoor plays an innocent simpleton falsely accused of murder. Nutan as his loyal supporter. A moving social drama with Shankar-Jaikishan's evergreen music including 'Sab Kuch Seekha Humne'.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1959,
    "duration": "166 min",
    "rating": 8,
    "videoUrl": "https://archive.org/embed/anari-1959-classic-hindi-film-raj-kapoor",
    "thumbnailUrl": "https://archive.org/services/img/anari-1959-classic-hindi-film-raj-kapoor",
    "featured": true,
    "trending": false,
    "status": "published",
    "views": 25000,
    "likes": 21000
  },
  {
    "title": "Chori Chori (1956)",
    "description": "Raj Kapoor and Nargis reunite in this delightful romantic comedy inspired by It Happened One Night. A runaway heiress and a street-smart man fall in love on a madcap journey across India. Shankar-Jaikishan's music is unforgettable.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1956,
    "duration": "158 min",
    "rating": 7.8,
    "videoUrl": "https://archive.org/embed/chori-chori-1956-raj-kapoor-nargis-classic-hindi-film",
    "thumbnailUrl": "https://archive.org/services/img/chori-chori-1956-raj-kapoor-nargis-classic-hindi-film",
    "featured": false,
    "trending": true,
    "status": "published",
    "views": 22000,
    "likes": 18500
  },
  {
    "title": "Aar Paar (1954)",
    "description": "Guru Dutt's stylish noir thriller about a taxi driver caught in a smuggling racket. Shot on the streets of Bombay with OP Nayyar's infectious music. Features the iconic 'Babuji Dheere Chalna' song. A milestone in Hindi cinema's film noir tradition.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1954,
    "duration": "146 min",
    "rating": 7.6,
    "videoUrl": "https://archive.org/embed/aar-paar-1954-guru-dutt-classic-hindi-film-shyama-jagdish-sethi-johnny-walker",
    "thumbnailUrl": "https://archive.org/services/img/aar-paar-1954-guru-dutt-classic-hindi-film-shyama-jagdish-sethi-johnny-walker",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 16000,
    "likes": 13200
  },
  {
    "title": "Mr. & Mrs. '55 (1955)",
    "description": "Guru Dutt and Madhubala in a sparkling social comedy about a marriage of convenience. A rich heiress must marry to inherit her fortune. OP Nayyar's peppy music makes this a joyful watch. A satire on patriarchy and women's liberation.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1955,
    "duration": "157 min",
    "rating": 7.7,
    "videoUrl": "https://archive.org/embed/mr-mrs-55-1955-guru-dutt-madhubala-classic-hindi-film",
    "thumbnailUrl": "https://archive.org/services/img/mr-mrs-55-1955-guru-dutt-madhubala-classic-hindi-film",
    "featured": false,
    "trending": true,
    "status": "published",
    "views": 19500,
    "likes": 16000
  },
  {
    "title": "Half Ticket (1962)",
    "description": "Kishore Kumar's comic genius shines as a man disguised as a child to buy cheaper train tickets. Madhubala in one of her last films. A hilarious romp with Kishore Kumar also singing the memorable songs. Pure entertainment from start to finish.",
    "type": "movie",
    "category": "Classic Hindi Comedy",
    "language": "Hindi",
    "year": 1962,
    "duration": "168 min",
    "rating": 7.9,
    "videoUrl": "https://archive.org/embed/half-ticket-1962-kishore-kumar-madhubala-kalidas-classic-hindi-comedy-film",
    "thumbnailUrl": "https://archive.org/services/img/half-ticket-1962-kishore-kumar-madhubala-kalidas-classic-hindi-comedy-film",
    "featured": true,
    "trending": true,
    "status": "published",
    "views": 27000,
    "likes": 23000
  },
  {
    "title": "Kohinoor (1960)",
    "description": "Dilip Kumar and Meena Kumari in a lavish costume drama set in the court of a medieval Indian kingdom. A prince and a court dancer fall in love amid palace intrigue. Naushad's music is sublime. Gorgeous Technicolor cinematography.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1960,
    "duration": "173 min",
    "rating": 7.4,
    "videoUrl": "https://archive.org/embed/kohinoor-1960-hindi.-1-cd.-dv-drip.-480p.-x-264.-aac.-arabic.-e.-subs.-tmb.-by.juleyano",
    "thumbnailUrl": "https://archive.org/services/img/kohinoor-1960-hindi.-1-cd.-dv-drip.-480p.-x-264.-aac.-arabic.-e.-subs.-tmb.-by.juleyano",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 15000,
    "likes": 12000
  },
  {
    "title": "Barsaat (1949)",
    "description": "Raj Kapoor's first major directorial success — two couples, two love stories, one tragic. The film that established RK Studios and made Nargis a superstar. Shankar-Jaikishan's music became a national phenomenon. The iconic rain songs are unforgettable.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1949,
    "duration": "171 min",
    "rating": 7.8,
    "videoUrl": "https://archive.org/embed/barsaat-1949-raj-kapoor-nargis-classic-hindi-film",
    "thumbnailUrl": "https://archive.org/services/img/barsaat-1949-raj-kapoor-nargis-classic-hindi-film",
    "featured": true,
    "trending": false,
    "status": "published",
    "views": 23000,
    "likes": 19500
  },
  {
    "title": "Kaagaz Ke Phool (1959)",
    "description": "Guru Dutt's tragic masterpiece about a film director's rise and fall. A commercial failure on release, now recognized as one of the greatest Indian films. Waheeda Rehman in a luminous performance. VK Murthy's stunning black-and-white cinematography.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1959,
    "duration": "148 min",
    "rating": 8.2,
    "videoUrl": "https://archive.org/embed/kaagaz-ke-phool-1959-guru-dutt-classic-hindi-film",
    "thumbnailUrl": "https://archive.org/services/img/kaagaz-ke-phool-1959-guru-dutt-classic-hindi-film",
    "featured": true,
    "trending": true,
    "status": "published",
    "views": 31000,
    "likes": 27500
  },
  {
    "title": "Devdas (1955)",
    "description": "Bimal Roy's definitive adaptation of Sarat Chandra's tragic romance. Dilip Kumar as the self-destructive lover, Suchitra Sen as Paro, Vyjayantimala as Chandramukhi. SD Burman's melancholic music perfectly captures doomed love. The gold standard for tragic romances.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1955,
    "duration": "159 min",
    "rating": 7.9,
    "videoUrl": "https://archive.org/embed/devdas-1955-bimal-roy-dilip-kumar-classic-hindi-film",
    "thumbnailUrl": "https://archive.org/services/img/devdas-1955-bimal-roy-dilip-kumar-classic-hindi-film",
    "featured": true,
    "trending": false,
    "status": "published",
    "views": 26000,
    "likes": 22000
  },
  {
    "title": "CID (1956)",
    "description": "Raj Khosla's stylish detective thriller starring Dev Anand as an inspector investigating a murder. A landmark in Hindi noir cinema with OP Nayyar's jazzy score. The song 'Aye Dil Hai Mushkil' became an instant classic. Taut, suspenseful storytelling.",
    "type": "movie",
    "category": "Classic Hindi Noir",
    "language": "Hindi",
    "year": 1956,
    "duration": "147 min",
    "rating": 7.7,
    "videoUrl": "https://archive.org/embed/cid-1956-dev-anand-classic-hindi-film-noir",
    "thumbnailUrl": "https://archive.org/services/img/cid-1956-dev-anand-classic-hindi-film-noir",
    "featured": false,
    "trending": true,
    "status": "published",
    "views": 20000,
    "likes": 16500
  },
  {
    "title": "Mother India (1957)",
    "description": "Mehboob Khan's epic saga of a poor woman's struggle to raise her sons and protect her land. Nargis in a towering performance. India's first submission to the Oscars (nominated for Best Foreign Film). A defining film of Indian independence and motherhood.",
    "type": "movie",
    "category": "Classic Hindi Epic",
    "language": "Hindi",
    "year": 1957,
    "duration": "172 min",
    "rating": 8.1,
    "videoUrl": "https://archive.org/embed/mother-india-1957-nargis-sunil-dutt-mehboob-khan",
    "thumbnailUrl": "https://archive.org/services/img/mother-india-1957-nargis-sunil-dutt-mehboob-khan",
    "featured": true,
    "trending": true,
    "status": "published",
    "views": 38000,
    "likes": 33000
  },
  {
    "title": "Sahib Bibi Aur Ghulam (1962)",
    "description": "Guru Dutt (possibly directed by him, credited to Abrar Alvi) — a decaying feudal mansion, a lonely wife, and a young servant. Meena Kumari's heartbreaking performance as an alcoholic aristocratic wife. A meditation on the death of zamindari culture.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1962,
    "duration": "152 min",
    "rating": 8.2,
    "videoUrl": "https://archive.org/embed/sahib-bibi-aur-ghulam-1962-meena-kumari-guru-dutt",
    "thumbnailUrl": "https://archive.org/services/img/sahib-bibi-aur-ghulam-1962-meena-kumari-guru-dutt",
    "featured": true,
    "trending": false,
    "status": "published",
    "views": 24000,
    "likes": 20500
  },
  {
    "title": "Jis Desh Mein Ganga Behti Hai (1960)",
    "description": "Raj Kapoor as Raju, a reformed dacoit who believes in the goodness of humanity. A social drama with a message of peace and non-violence. Padmini as the village belle. Shankar-Jaikishan's patriotic and romantic songs are timeless.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1960,
    "duration": "168 min",
    "rating": 7.6,
    "videoUrl": "https://archive.org/embed/jis-desh-mein-ganga-behti-hai-1960-raj-kapoor",
    "thumbnailUrl": "https://archive.org/services/img/jis-desh-mein-ganga-behti-hai-1960-raj-kapoor",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 17000,
    "likes": 14000
  },
  {
    "title": "Mughal-e-Azam (1960)",
    "description": "K. Asif's legendary magnum opus — Prince Salim's forbidden love for court dancer Anarkali. Dilip Kumar, Madhubala and Prithviraj Kapoor in iconic roles. Naushad's music is immortal. Took 16 years to make. The pinnacle of Hindi cinema's golden age.",
    "type": "movie",
    "category": "Classic Hindi Epic",
    "language": "Hindi",
    "year": 1960,
    "duration": "197 min",
    "rating": 8.7,
    "videoUrl": "https://archive.org/embed/mughal-e-azam-1960-dilip-kumar-madhubala",
    "thumbnailUrl": "https://archive.org/services/img/mughal-e-azam-1960-dilip-kumar-madhubala",
    "featured": true,
    "trending": true,
    "status": "published",
    "views": 52000,
    "likes": 46000
  },
  {
    "title": "Naya Daur (1957)",
    "description": "BR Chopra's social drama about modernization vs tradition. A tonga driver races a bus to prove human will can triumph over machines. Dilip Kumar and Vyjayantimala lead a spirited ensemble. OP Nayyar's rousing music captures rural India's pride.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1957,
    "duration": "173 min",
    "rating": 7.8,
    "videoUrl": "https://archive.org/embed/naya-daur-1957-dilip-kumar-vyjayantimala",
    "thumbnailUrl": "https://archive.org/services/img/naya-daur-1957-dilip-kumar-vyjayantimala",
    "featured": false,
    "trending": true,
    "status": "published",
    "views": 21000,
    "likes": 17500
  },
  {
    "title": "Bandini (1963)",
    "description": "Bimal Roy's swan song — a female prisoner's journey of redemption. Nutan in a career-best performance as Kalyani. Ashok Kumar and Dharmendra as two men who love her. SD Burman's music is sublime. A feminist masterpiece ahead of its time.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1963,
    "duration": "157 min",
    "rating": 8,
    "videoUrl": "https://archive.org/embed/bandini-1963-nutan-bimal-roy",
    "thumbnailUrl": "https://archive.org/services/img/bandini-1963-nutan-bimal-roy",
    "featured": true,
    "trending": false,
    "status": "published",
    "views": 19000,
    "likes": 16200
  },
  {
    "title": "Sujata (1959)",
    "description": "Bimal Roy's sensitive portrayal of caste discrimination. A Brahmin family adopts an 'untouchable' girl. Nutan as Sujata and Sunil Dutt as her progressive lover. A plea for social equality wrapped in a touching love story. SD Burman's music enhances the emotional core.",
    "type": "movie",
    "category": "Classic Hindi Social",
    "language": "Hindi",
    "year": 1959,
    "duration": "161 min",
    "rating": 7.9,
    "videoUrl": "https://archive.org/embed/sujata-1959-nutan-bimal-roy",
    "thumbnailUrl": "https://archive.org/services/img/sujata-1959-nutan-bimal-roy",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 16500,
    "likes": 13800
  },
  {
    "title": "Chalti Ka Naam Gaadi (1958)",
    "description": "The three Kapoor brothers (Ashok, Anoop, Kishore) in a madcap musical comedy about three bachelor mechanics who swear off women. Madhubala brings chaos to their lives. Kishore Kumar's music is infectious. One of Hindi cinema's best comedies.",
    "type": "movie",
    "category": "Classic Hindi Comedy",
    "language": "Hindi",
    "year": 1958,
    "duration": "173 min",
    "rating": 8,
    "videoUrl": "https://archive.org/embed/chalti-ka-naam-gaadi-1958-kishore-kumar-madhubala",
    "thumbnailUrl": "https://archive.org/services/img/chalti-ka-naam-gaadi-1958-kishore-kumar-madhubala",
    "featured": true,
    "trending": true,
    "status": "published",
    "views": 29000,
    "likes": 25000
  },
  {
    "title": "Jagriti (1954)",
    "description": "Satyen Bose's inspiring film about a teacher who transforms delinquent boys through compassion. Abhi Bhattacharya leads a powerful ensemble. The patriotic song 'Aao Bachcho Tumhe Dikhayein' became a school anthem across India. Social cinema at its finest.",
    "type": "movie",
    "category": "Classic Hindi Social",
    "language": "Hindi",
    "year": 1954,
    "duration": "158 min",
    "rating": 8.1,
    "videoUrl": "https://archive.org/embed/jagriti-1954-satyen-bose-classic-hindi-film",
    "thumbnailUrl": "https://archive.org/services/img/jagriti-1954-satyen-bose-classic-hindi-film",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 14000,
    "likes": 11800
  },
  {
    "title": "Taxi Driver (1954)",
    "description": "Chetan Anand's romantic thriller — Dev Anand as a taxi driver who becomes embroiled in a smuggling ring while falling for a mysterious woman. Kalpana Kartik brings grace. SD Burman's music including 'Jayen Toh Jayen Kahan' became classics.",
    "type": "movie",
    "category": "Classic Hindi Noir",
    "language": "Hindi",
    "year": 1954,
    "duration": "132 min",
    "rating": 7.5,
    "videoUrl": "https://archive.org/embed/taxi-driver-1954-dev-anand-chetan-anand",
    "thumbnailUrl": "https://archive.org/services/img/taxi-driver-1954-dev-anand-chetan-anand",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 15000,
    "likes": 12500
  },
  {
    "title": "Nagin (1954)",
    "description": "A snake-woman's tale of love and revenge. Vyjayantimala in a career-making performance. Hemant Kumar's iconic music including the sensuous 'Man Dole Mera Tan Dole' became a national craze. One of the highest-grossing films of the 1950s.",
    "type": "movie",
    "category": "Classic Hindi Fantasy",
    "language": "Hindi",
    "year": 1954,
    "duration": "148 min",
    "rating": 7.3,
    "videoUrl": "https://archive.org/embed/nagin-1954-vyjayantimala-classic-hindi-film",
    "thumbnailUrl": "https://archive.org/services/img/nagin-1954-vyjayantimala-classic-hindi-film",
    "featured": false,
    "trending": true,
    "status": "published",
    "views": 23000,
    "likes": 19000
  },
  {
    "title": "Boot Polish (1954)",
    "description": "Raj Kapoor's production about two orphan siblings who shine shoes for a living. Prakash Arora's direction focuses on child labor and poverty with sensitivity. The children's performances are heartbreaking. Shankar-Jaikishan's music enhances the emotional journey.",
    "type": "movie",
    "category": "Classic Hindi Social",
    "language": "Hindi",
    "year": 1954,
    "duration": "149 min",
    "rating": 7.8,
    "videoUrl": "https://archive.org/embed/boot-polish-1954-raj-kapoor-production",
    "thumbnailUrl": "https://archive.org/services/img/boot-polish-1954-raj-kapoor-production",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 13000,
    "likes": 10800
  },
  {
    "title": "Funtoosh (1956)",
    "description": "Dev Anand in a triple role — a street singer, a rich heir, and a crook. A delightful comedy of mistaken identities. Sheila Ramani adds charm. SD Burman's playful music makes this a joyride. Light-hearted entertainment at its best.",
    "type": "movie",
    "category": "Classic Hindi Comedy",
    "language": "Hindi",
    "year": 1956,
    "duration": "145 min",
    "rating": 7.2,
    "videoUrl": "https://archive.org/embed/funtoosh-1956-hindi.-dv-drip.-480p.x-264.-aac.-ex-dt-by.juleyano",
    "thumbnailUrl": "https://archive.org/services/img/funtoosh-1956-hindi.-dv-drip.-480p.x-264.-aac.-ex-dt-by.juleyano",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 12000,
    "likes": 9800
  },
  {
    "title": "Gumrah (1963)",
    "description": "BR Chopra's adaptation of an American thriller about a woman caught in a love triangle and a smuggling plot. Mala Sinha, Sunil Dutt and Ashok Kumar in intense performances. Ravi's music heightens the suspense. A taut psychological drama.",
    "type": "movie",
    "category": "Classic Hindi Thriller",
    "language": "Hindi",
    "year": 1963,
    "duration": "151 min",
    "rating": 7.6,
    "videoUrl": "https://archive.org/embed/gumrah-1963-mala-sinha-sunil-dutt-br-chopra",
    "thumbnailUrl": "https://archive.org/services/img/gumrah-1963-mala-sinha-sunil-dutt-br-chopra",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 14500,
    "likes": 12000
  },
  {
    "title": "Dil Ek Mandir (1963)",
    "description": "CV Sridhar's emotional drama about a doctor torn between duty and love. Rajendra Kumar, Meena Kumari and Raaj Kumar in a tragic triangle. Shankar-Jaikishan's soulful music complements the melodrama. A tearjerker that became a major hit.",
    "type": "movie",
    "category": "Classic Hindi Drama",
    "language": "Hindi",
    "year": 1963,
    "duration": "145 min",
    "rating": 7.4,
    "videoUrl": "https://archive.org/embed/dil-ek-mandir-1963-rajendra-kumar-meena-kumari",
    "thumbnailUrl": "https://archive.org/services/img/dil-ek-mandir-1963-rajendra-kumar-meena-kumari",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 13500,
    "likes": 11200
  },
  {
    "title": "Solva Saal (1958)",
    "description": "Raj Khosla's charming romance — a young couple's love story complicated by family opposition. Dev Anand and Waheeda Rehman's first pairing. SD Burman's youthful music captured a generation's aspirations. Fresh, energetic and romantic.",
    "type": "movie",
    "category": "Classic Hindi Romance",
    "language": "Hindi",
    "year": 1958,
    "duration": "164 min",
    "rating": 7.5,
    "videoUrl": "https://archive.org/embed/solva-saal-1958-dev-anand-waheeda-rehman",
    "thumbnailUrl": "https://archive.org/services/img/solva-saal-1958-dev-anand-waheeda-rehman",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 16000,
    "likes": 13500
  },
  {
    "title": "Rajkumar (1964)",
    "description": "K. Shankar's swashbuckling adventure — Shammi Kapoor as a prince separated from his kingdom, living as a commoner. Sadhana as his love interest. Shankar-Jaikishan's music is thrilling. Action, romance and comedy in perfect balance.",
    "type": "movie",
    "category": "Classic Hindi Adventure",
    "language": "Hindi",
    "year": 1964,
    "duration": "160 min",
    "rating": 7.3,
    "videoUrl": "https://archive.org/embed/rajkumar-1964-hindi.-dv-drip.-480p.x-264.-ac-3.-esub.-5.1-ch.-xmr-ex-d.-by-juleyano",
    "thumbnailUrl": "https://archive.org/services/img/rajkumar-1964-hindi.-dv-drip.-480p.x-264.-ac-3.-esub.-5.1-ch.-xmr-ex-d.-by-juleyano",
    "featured": false,
    "trending": true,
    "status": "published",
    "views": 18000,
    "likes": 15000
  },
  {
    "title": "Waqt (1965)",
    "description": "BR Chopra's influential multi-starrer — a family separated by an earthquake reunites years later without knowing it. Sunil Dutt, Raaj Kumar, Shashi Kapoor, Sadhana. Introduced the 'lost and found' formula to Bollywood. Ravi's music is unforgettable.",
    "type": "movie",
    "category": "Classic Hindi Drama",
    "language": "Hindi",
    "year": 1965,
    "duration": "206 min",
    "rating": 7.7,
    "videoUrl": "https://archive.org/embed/waqt-1965-br-chopra-sunil-dutt-raaj-kumar",
    "thumbnailUrl": "https://archive.org/services/img/waqt-1965-br-chopra-sunil-dutt-raaj-kumar",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 20000,
    "likes": 16800
  },
  {
    "title": "Aah (1953)",
    "description": "Raja Nawathe's tragic romance — Raj Kapoor as a dying man who pushes away the woman he loves. Nargis in a heartbreaking performance. Shankar-Jaikishan's melancholic music including 'Raja Ki Aayegi Baraat' became classics. A beautiful tearjerker.",
    "type": "movie",
    "category": "Classic Hindi Romance",
    "language": "Hindi",
    "year": 1953,
    "duration": "159 min",
    "rating": 7.5,
    "videoUrl": "https://archive.org/embed/aah-1953-raj-kapoor-nargis",
    "thumbnailUrl": "https://archive.org/services/img/aah-1953-raj-kapoor-nargis",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 14000,
    "likes": 11500
  },
  {
    "title": "Parineeta (1953)",
    "description": "Bimal Roy's adaptation of Sarat Chandra's novel about middle-class Bengali life. Ashok Kumar and Meena Kumari in a tender love story complicated by class differences. Beautiful black-and-white cinematography captures 1930s Kolkata. A mature, literary romance.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1953,
    "duration": "151 min",
    "rating": 7.6,
    "videoUrl": "https://archive.org/embed/parineeta-1953-bimal-roy-ashok-kumar-meena-kumari",
    "thumbnailUrl": "https://archive.org/services/img/parineeta-1953-bimal-roy-ashok-kumar-meena-kumari",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 12500,
    "likes": 10300
  },
  {
    "title": "Hum Dono (1961)",
    "description": "Amarjeet's ingenious story — Dev Anand in a double role as an army officer and a lookalike. Sadhana and Nanda as the leading ladies. A wartime romance with Jaidev's haunting music. The rain song 'Abhi Na Jao Chhod Kar' is legendary.",
    "type": "movie",
    "category": "Classic Hindi",
    "language": "Hindi",
    "year": 1961,
    "duration": "168 min",
    "rating": 7.9,
    "videoUrl": "https://archive.org/embed/hum-dono-1961-dev-anand-sadhana-nanda",
    "thumbnailUrl": "https://archive.org/services/img/hum-dono-1961-dev-anand-sadhana-nanda",
    "featured": true,
    "trending": false,
    "status": "published",
    "views": 22000,
    "likes": 18800
  },
  {
    "title": "Tere Ghar Ke Samne (1963)",
    "description": "Vijay Anand's breezy romantic comedy — two neighboring families at war, their children fall in love Romeo-Juliet style. Dev Anand and Nutan sparkle. SD Burman's music is delightful. A lighthearted charmer from start to finish.",
    "type": "movie",
    "category": "Classic Hindi Comedy",
    "language": "Hindi",
    "year": 1963,
    "duration": "152 min",
    "rating": 7.4,
    "videoUrl": "https://archive.org/embed/tere-ghar-ke-samne-1963-dev-anand-nutan",
    "thumbnailUrl": "https://archive.org/services/img/tere-ghar-ke-samne-1963-dev-anand-nutan",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 15500,
    "likes": 12800
  },
  {
    "title": "Yahudi (1958)",
    "description": "Bimal Roy's epic set in ancient Rome — a Jewish prince falls in love with the Roman Emperor's daughter. Dilip Kumar, Meena Kumari and Sohrab Modi in powerful performances. Shankar-Jaikishan's grand music matches the scale. A lavish historical romance.",
    "type": "movie",
    "category": "Classic Hindi Epic",
    "language": "Hindi",
    "year": 1958,
    "duration": "170 min",
    "rating": 7.7,
    "videoUrl": "https://archive.org/embed/yahudi-1958-bimal-roy-dilip-kumar-meena-kumari",
    "thumbnailUrl": "https://archive.org/services/img/yahudi-1958-bimal-roy-dilip-kumar-meena-kumari",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 16500,
    "likes": 13800
  },
  {
    "title": "Daag (1952)",
    "description": "Amiya Chakravarty's tragic romance — a man accidentally kills his romantic rival and runs away, only to return years later with a new identity. Dilip Kumar won the first Filmfare Best Actor award. Shankar-Jaikishan's music heightens the melodrama.",
    "type": "movie",
    "category": "Classic Hindi Drama",
    "language": "Hindi",
    "year": 1952,
    "duration": "145 min",
    "rating": 7.5,
    "videoUrl": "https://archive.org/embed/daag-1952-dilip-kumar-nimmi",
    "thumbnailUrl": "https://archive.org/services/img/daag-1952-dilip-kumar-nimmi",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 13000,
    "likes": 10800
  },
  {
    "title": "Parakh (1960)",
    "description": "Bimal Roy's satire on greed and morality — a millionaire tests a village by offering money to see who stays honest. Sadhana's debut film. Salil Chowdhury's music is excellent. A sharp commentary on human nature and materialism. Thought-provoking cinema.",
    "type": "movie",
    "category": "Classic Hindi Social",
    "language": "Hindi",
    "year": 1960,
    "duration": "164 min",
    "rating": 7.8,
    "videoUrl": "https://archive.org/embed/parakh-1960-bimal-roy-sadhana-debut",
    "thumbnailUrl": "https://archive.org/services/img/parakh-1960-bimal-roy-sadhana-debut",
    "featured": false,
    "trending": false,
    "status": "published",
    "views": 11000,
    "likes": 9200
  },
  {
    "title": "Chaudhvin Ka Chand (1960)",
    "description": "M. Sadiq's romantic musical — a love triangle set against Lucknow's cultural backdrop. Guru Dutt, Waheeda Rehman and Rehman in a story of friendship and sacrifice. Ravi's music including the title song became legendary. Gorgeously shot in Technicolor.",
    "type": "movie",
    "category": "Classic Hindi Romance",
    "language": "Hindi",
    "year": 1960,
    "duration": "163 min",
    "rating": 7.9,
    "videoUrl": "https://archive.org/embed/chaudhvin-ka-chand-1960-guru-dutt-waheeda-rehman",
    "thumbnailUrl": "https://archive.org/services/img/chaudhvin-ka-chand-1960-guru-dutt-waheeda-rehman",
    "featured": true,
    "trending": true,
    "status": "published",
    "views": 25000,
    "likes": 21500
  },

                // ================================================
          
      // ===========================
      // SERIES (10 Classic Indian TV)
      // ===========================
      {
        title: "Ramayana (1987) - Episode 1",
        description: "Ramanand Sagar's iconic Doordarshan serial. Episode 1: The story begins in Ayodhya with King Dasharatha and the birth of Lord Rama. Holds the Guinness World Record for most-watched TV show. Arun Govil as Rama and Deepika Chikhalia as Sita became household names.",
        type: "series",
        category: "Mythological",
        language: "Hindi",
        year: 1987,
        duration: "45 min/ep",
        rating: 9.2,
        videoUrl: "https://archive.org/embed/ramayana-1987-episode-1",
        thumbnailUrl: "https://archive.org/services/img/ramayana-1987-episode-1",
        featured: true,
        trending: true,
        status: "published",
        views: 89000,
        likes: 78000
      },
      {
        title: "Mahabharat (1988) - Episode 1",
        description: "B.R. Chopra's magnum opus. Episode 1 introduces the Kuru dynasty. With Mukesh Khanna as Bhishma and Nitish Bharadwaj as Krishna, this serial redefined Indian television. 94 episodes that captivated a billion viewers every Sunday morning.",
        type: "series",
        category: "Mythological",
        language: "Hindi",
        year: 1988,
        duration: "45 min/ep",
        rating: 9.1,
        videoUrl: "https://archive.org/embed/mahabharat-1988-episode-1",
        thumbnailUrl: "https://archive.org/services/img/mahabharat-1988-episode-1",
        featured: true,
        trending: true,
        status: "published",
        views: 76000,
        likes: 67000
      },
      {
        title: "Byomkesh Bakshi (1993) - Season 1",
        description: "Doordarshan's beloved detective series. Rajit Kapur plays the truth-seeker Byomkesh Bakshi in complex mysteries set in 1940s Kolkata. Acclaimed for its authentic period atmosphere, intelligent writing, and stellar performances. India's Sherlock Holmes.",
        type: "series",
        category: "Mystery Drama",
        language: "Hindi",
        year: 1993,
        duration: "50 min/ep",
        rating: 8.7,
        videoUrl: "https://archive.org/embed/ByomkeshBakshi1993Season1",
        thumbnailUrl: "https://archive.org/services/img/ByomkeshBakshi1993Season1",
        featured: false,
        trending: true,
        status: "published",
        views: 34000,
        likes: 28500
      },
      {
        title: "Malgudi Days (1987) - Season 1",
        description: "Shankar Nag's timeless adaptation of R.K. Narayan's stories of the fictional South Indian town of Malgudi. Young Swami's charming adventures, the wise Raju, and colorful characters. The nostalgic theme by L. Subramaniam is forever etched in memory.",
        type: "series",
        category: "Family Drama",
        language: "Hindi",
        year: 1987,
        duration: "25 min/ep",
        rating: 9.0,
        videoUrl: "https://archive.org/embed/MalgudiDays1987Season1",
        thumbnailUrl: "https://archive.org/services/img/MalgudiDays1987Season1",
        featured: true,
        trending: false,
        status: "published",
        views: 41000,
        likes: 36500
      },
      {
        title: "Vikram aur Betaal (1985)",
        description: "King Vikramaditya carries a corpse possessed by the spirit Betaal, who poses a riddle each episode. A beloved Doordarshan mythological-folk series that mesmerised a generation. Arun Govil as Vikram before he became Rama.",
        type: "series",
        category: "Mythology Folk",
        language: "Hindi",
        year: 1985,
        duration: "25 min/ep",
        rating: 8.5,
        videoUrl: "https://archive.org/embed/VikramaaurBetaal1985",
        thumbnailUrl: "https://archive.org/services/img/VikramaaurBetaal1985",
        featured: false,
        trending: true,
        status: "published",
        views: 27000,
        likes: 22000
      },
      {
        title: "Buniyaad (1986)",
        description: "India's most celebrated family saga: the Haveli Ram family from Partition 1947 to the 1980s. Directed by Ramesh Sippy, written by Manohar Shyam Joshi. The first major prime-time serial on Doordarshan. A landmark in Indian television history.",
        type: "series",
        category: "Family Saga",
        language: "Hindi",
        year: 1986,
        duration: "50 min/ep",
        rating: 8.8,
        videoUrl: "https://archive.org/embed/Buniyaad1986",
        thumbnailUrl: "https://archive.org/services/img/Buniyaad1986",
        featured: true,
        trending: false,
        status: "published",
        views: 31000,
        likes: 26000
      },
      {
        title: "Hum Log (1984)",
        description: "India's first soap opera: the Rastogi family's everyday struggles. 156 episodes, 50 million viewers per episode. Changed the landscape of Indian television forever. Ashok Kumar as the narrator brought gravitas to this pioneering social drama.",
        type: "series",
        category: "Social Drama",
        language: "Hindi",
        year: 1984,
        duration: "23 min/ep",
        rating: 8.3,
        videoUrl: "https://archive.org/embed/HumLog1984",
        thumbnailUrl: "https://archive.org/services/img/HumLog1984",
        featured: false,
        trending: false,
        status: "published",
        views: 18000,
        likes: 14500
      },
      {
        title: "Tenali Rama (1988)",
        description: "The witty tales of Tenali Rama, court jester of Emperor Krishnadevaraya. Each episode showcases clever solutions to impossible problems. A beloved Tamil/Telugu DD series that taught life lessons through humor and intelligence.",
        type: "series",
        category: "Historical Comedy",
        language: "Tamil",
        year: 1988,
        duration: "25 min/ep",
        rating: 8.1,
        videoUrl: "https://archive.org/embed/TenaliRama1988TamilSeries",
        thumbnailUrl: "https://archive.org/services/img/TenaliRama1988TamilSeries",
        featured: false,
        trending: true,
        status: "published",
        views: 23000,
        likes: 19000
      },
      {
        title: "Circus (1989)",
        description: "Shah Rukh Khan's television debut: a young trainee at a traveling circus discovers friendships and dreams. Directed by Aziz Mirza. The launch pad for the King of Bollywood. Renuka Shahane co-stars in this heartwarming drama.",
        type: "series",
        category: "Drama",
        language: "Hindi",
        year: 1989,
        duration: "45 min/ep",
        rating: 8.4,
        videoUrl: "https://archive.org/embed/Circus1989DoordarshantvsSerialShahrukhKhan",
        thumbnailUrl: "https://archive.org/services/img/Circus1989DoordarshantvsSerialShahrukhKhan",
        featured: true,
        trending: true,
        status: "published",
        views: 44000,
        likes: 38000
      },
      {
        title: "Nukkad (1986)",
        description: "Ensemble drama about everyday lives of people at a Delhi street corner. Two seasons of raw honesty, humor and empathy. One of Doordarshan's most beloved and enduring series. Kundan Shah and Saeed Mirza's masterpiece of realist television.",
        type: "series",
        category: "Social Drama",
        language: "Hindi",
        year: 1986,
        duration: "25 min/ep",
        rating: 8.6,
        videoUrl: "https://archive.org/embed/Nukkad1986Season1",
        thumbnailUrl: "https://archive.org/services/img/Nukkad1986Season1",
        featured: false,
        trending: false,
        status: "published",
        views: 19500,
        likes: 16200
      },
      // DOCUMENTARIES (10) — All public domain
                // ================================================
                {
                    title: 'Gandhi — Archival Documentary (1962)',
                    description: 'Rare archival footage of Mahatma Gandhi — his speeches, the Salt March, the Independence movement. Features actual newsreel footage from British Pathé and Films Division of India.',
                    type: 'documentary', category: 'Historical', language: 'English',
                    year: 1962, duration: '62 min', rating: 8.9,
                    videoUrl:     'https://archive.org/embed/gov.archives.arc.43754',
                    thumbnailUrl: 'https://archive.org/services/img/gov.archives.arc.43754',
                    featured: true, trending: false, status: 'published', views: 31000, likes: 26500
                },
                {
                    title: 'Night and Fog (1956)',
                    description: "Alain Resnais' haunting documentary about Nazi concentration camps — alternating colour present-day footage with black-and-white archival film. One of the most powerful anti-war films ever made.",
                    type: 'documentary', category: 'War History', language: 'French',
                    year: 1956, duration: '32 min', rating: 8.6,
                    videoUrl:     'https://archive.org/embed/NightAndFog1955',
                    thumbnailUrl: 'https://archive.org/services/img/NightAndFog1955',
                    featured: true, trending: false, status: 'published', views: 22000, likes: 18500
                },
                {
                    title: 'Nanook of the North (1922)',
                    description: "The world's first feature-length documentary. Robert Flaherty's portrait of Inuit life — Nanook and his family hunting and surviving the brutal Arctic. A foundational work of world cinema.",
                    type: 'documentary', category: 'Anthropology', language: 'Silent',
                    year: 1922, duration: '79 min', rating: 7.8,
                    videoUrl:     'https://archive.org/embed/nanook-of-the-north',
                    thumbnailUrl: 'https://archive.org/services/img/nanook-of-the-north',
                    featured: true, trending: false, status: 'published', views: 17000, likes: 13500
                },
                {
                    title: 'Man of Aran (1934)',
                    description: "Robert Flaherty's masterpiece about the harsh life of Irish fisherfolk on the Aran Islands. Stunning cinematography of elemental struggle. One of the greatest documentaries ever made.",
                    type: 'documentary', category: 'Nature & People', language: 'English',
                    year: 1934, duration: '76 min', rating: 7.9,
                    videoUrl:     'https://archive.org/embed/ManOfAran',
                    thumbnailUrl: 'https://archive.org/services/img/ManOfAran',
                    featured: false, trending: true, status: 'published', views: 11500, likes: 9200
                },
                {
                    title: 'The City (1939)',
                    description: 'A landmark American documentary about urban planning — industrial cities vs planned communities. Score by Aaron Copland. Listed in the US National Film Registry.',
                    type: 'documentary', category: 'Urban History', language: 'English',
                    year: 1939, duration: '44 min', rating: 7.8,
                    videoUrl:     'https://archive.org/embed/theCity',
                    thumbnailUrl: 'https://archive.org/services/img/theCity',
                    featured: false, trending: false, status: 'published', views: 7200, likes: 5400
                },
                {
                    title: 'Housing Problems (1935)',
                    description: 'Pioneering British social documentary where slum dwellers speak directly to camera — one of the first uses of the interview form in film. A landmark of social realist documentary.',
                    type: 'documentary', category: 'Social History', language: 'English',
                    year: 1935, duration: '15 min', rating: 7.3,
                    videoUrl:     'https://archive.org/embed/HousingProblems',
                    thumbnailUrl: 'https://archive.org/services/img/HousingProblems',
                    featured: false, trending: false, status: 'published', views: 5100, likes: 3900
                },
                {
                    title: 'The Plow That Broke the Plains (1936)',
                    description: "US government documentary about the Dust Bowl catastrophe and decades of over-farming. Score by Virgil Thomson. One of America's first great government-produced documentary films.",
                    type: 'documentary', category: 'Environmental', language: 'English',
                    year: 1936, duration: '28 min', rating: 7.5,
                    videoUrl:     'https://archive.org/embed/ThePlowThatBrokethePlains',
                    thumbnailUrl: 'https://archive.org/services/img/ThePlowThatBrokethePlains',
                    featured: false, trending: false, status: 'published', views: 6400, likes: 4900
                },
                {
                    title: 'Listen to Britain (1942)',
                    description: "Humphrey Jennings' impressionistic wartime documentary — Britain's soundscape during WWII. No narrator, just sounds and images of factories, music halls and streets. A masterpiece of the form.",
                    type: 'documentary', category: 'WWII History', language: 'English',
                    year: 1942, duration: '19 min', rating: 8.0,
                    videoUrl:     'https://archive.org/embed/ListentoBritain1942',
                    thumbnailUrl: 'https://archive.org/services/img/ListentoBritain1942',
                    featured: false, trending: false, status: 'published', views: 9000, likes: 7200
                },
                {
                    title: 'India: A Nation Under Siege (1944)',
                    description: "Rare WWII-era documentary about India's role in the Allied war effort — Indian Army, industrial mobilization and colonial social fabric. A time capsule from the US National Archives.",
                    type: 'documentary', category: 'WWII History', language: 'English',
                    year: 1944, duration: '18 min', rating: 7.6,
                    videoUrl:     'https://archive.org/embed/india-a-nation-under-siege-1944',
                    thumbnailUrl: 'https://archive.org/services/img/india-a-nation-under-siege-1944',
                    featured: false, trending: false, status: 'published', views: 8500, likes: 6800
                },
                {
                    title: 'Triumph of the Will (1935)',
                    description: "Leni Riefenstahl's groundbreaking and controversial documentary of the 1934 Nuremberg rally. Widely studied as the supreme example of propaganda cinema and a technical landmark of filmmaking.",
                    type: 'documentary', category: 'Historical Study', language: 'German',
                    year: 1935, duration: '114 min', rating: 7.4,
                    videoUrl:     'https://archive.org/embed/TriumphOfTheWill',
                    thumbnailUrl: 'https://archive.org/services/img/TriumphOfTheWill',
                    featured: false, trending: false, status: 'published', views: 14000, likes: 8500
                },

                // ================================================
                // LIVE (10) — Indian classical music legends
                // ================================================
                {
                    title: 'Ravi Shankar — Monterey Pop Festival (1967)',
                    description: "Pandit Ravi Shankar's historic sitar performance at Monterey that introduced Indian classical music to Western rock audiences. A transcendent raga that moved the crowd to meditation.",
                    type: 'live', category: 'Classical Music', language: 'Instrumental',
                    year: 1967, duration: '15 min', rating: 9.3,
                    videoUrl:     'https://archive.org/embed/RaviShankarMonterey1967',
                    thumbnailUrl: 'https://archive.org/services/img/RaviShankarMonterey1967',
                    featured: true, trending: true, status: 'published', views: 48000, likes: 43000
                },
                {
                    title: 'M.S. Subbulakshmi — Carnegie Hall (1977)',
                    description: "M.S. Subbulakshmi's landmark Carnegie Hall performance — the first Carnatic vocalist to perform there. Legendary renditions of Bhaja Govindam and Venkateswara Suprabhatham.",
                    type: 'live', category: 'Carnatic Vocal', language: 'Tamil/Sanskrit',
                    year: 1977, duration: '96 min', rating: 9.4,
                    videoUrl:     'https://archive.org/embed/MSSubbulakshmiCarnegieHall1977',
                    thumbnailUrl: 'https://archive.org/services/img/MSSubbulakshmiCarnegieHall1977',
                    featured: true, trending: true, status: 'published', views: 37000, likes: 33500
                },
                {
                    title: 'Kishore Kumar — Live Concert Ahmedabad (1985)',
                    description: 'One of the last great recordings of Kishore Kumar — performing iconic Bollywood songs in a packed Ahmedabad stadium, two years before his passing. Includes Mohammed Rafi tributes.',
                    type: 'live', category: 'Bollywood Music', language: 'Hindi',
                    year: 1985, duration: '120 min', rating: 9.0,
                    videoUrl:     'https://archive.org/embed/KishoreKumarLiveAhmedabad1985',
                    thumbnailUrl: 'https://archive.org/services/img/KishoreKumarLiveAhmedabad1985',
                    featured: true, trending: true, status: 'published', views: 54000, likes: 49000
                },
                {
                    title: 'Lata Mangeshkar — Royal Albert Hall (1974)',
                    description: "The Nightingale of India performing live in London — Lag Ja Gale, Aye Mere Watan Ke Logon, and Tere Bina Zindagi Se. The first major Bollywood concert at the Royal Albert Hall.",
                    type: 'live', category: 'Bollywood Music', language: 'Hindi',
                    year: 1974, duration: '90 min', rating: 9.0,
                    videoUrl:     'https://archive.org/embed/LataMangeshkarLiveLondon1974',
                    thumbnailUrl: 'https://archive.org/services/img/LataMangeshkarLiveLondon1974',
                    featured: false, trending: true, status: 'published', views: 41000, likes: 36500
                },
                {
                    title: 'Bismillah Khan — Shehnai at Varanasi Ghat',
                    description: "Bharat Ratna Ustad Bismillah Khan performing shehnai at the sacred ghats of Varanasi — the city he never left. An irreplaceable document of North Indian classical tradition.",
                    type: 'live', category: 'Classical Music', language: 'Instrumental',
                    year: 1980, duration: '48 min', rating: 9.1,
                    videoUrl:     'https://archive.org/embed/BismillahKhanShehnaiVaranasi',
                    thumbnailUrl: 'https://archive.org/services/img/BismillahKhanShehnaiVaranasi',
                    featured: true, trending: false, status: 'published', views: 28000, likes: 24000
                },
                {
                    title: 'Zakir Hussain — Tabla at WOMAD (1982)',
                    description: "Ustad Zakir Hussain's breathtaking tabla solo and jugalbandi at the inaugural WOMAD festival. The performance that made Zakir Hussain an international superstar.",
                    type: 'live', category: 'Classical Music', language: 'Instrumental',
                    year: 1982, duration: '55 min', rating: 9.2,
                    videoUrl:     'https://archive.org/embed/ZakirHussainTablaWOMAD1982',
                    thumbnailUrl: 'https://archive.org/services/img/ZakirHussainTablaWOMAD1982',
                    featured: false, trending: false, status: 'published', views: 23000, likes: 20000
                },
                {
                    title: 'Bhimsen Joshi — Sawai Gandharva Festival (1976)',
                    description: "Pandit Bhimsen Joshi performing Raag Bhairav and Miyan Ki Malhar at the Sawai Gandharva Festival, Pune. The definitive live recording of the Kirana Gharana Hindustani vocal tradition.",
                    type: 'live', category: 'Hindustani Vocal', language: 'Hindi/Sanskrit',
                    year: 1976, duration: '80 min', rating: 9.3,
                    videoUrl:     'https://archive.org/embed/BhimsenJoshiSawaiGandharva1976',
                    thumbnailUrl: 'https://archive.org/services/img/BhimsenJoshiSawaiGandharva1976',
                    featured: true, trending: false, status: 'published', views: 17500, likes: 15000
                },
                {
                    title: 'Girija Devi — Thumri at Benares (1983)',
                    description: "Padma Vibhushan Girija Devi, Queen of Thumri, performing in Varanasi. A rare live recording of thumri, dadra and kajri — devotion, romance and playfulness at their finest.",
                    type: 'live', category: 'Hindustani Semi-classical', language: 'Bhojpuri/Hindi',
                    year: 1983, duration: '65 min', rating: 8.8,
                    videoUrl:     'https://archive.org/embed/GirijaDeviThumriBenares1983',
                    thumbnailUrl: 'https://archive.org/services/img/GirijaDeviThumriBenares1983',
                    featured: false, trending: false, status: 'published', views: 12000, likes: 10200
                },
                {
                    title: 'Ali Akbar Khan — Sarod Recital (1955)',
                    description: "Ustad Ali Akbar Khan's celebrated sarod recital — one of the first Indian classical LPs released in America. Disciple of Baba Allauddin Khan and brother-in-law of Ravi Shankar.",
                    type: 'live', category: 'Hindustani Instrumental', language: 'Instrumental',
                    year: 1955, duration: '52 min', rating: 9.0,
                    videoUrl:     'https://archive.org/embed/AliAkbarKhanSarodRecital1955',
                    thumbnailUrl: 'https://archive.org/services/img/AliAkbarKhanSarodRecital1955',
                    featured: false, trending: false, status: 'published', views: 14200, likes: 12500
                },
                {
                    title: 'Nadaswaram Classical Concert (1970)',
                    description: 'T.N. Rajarathnam Pillai performing the nadaswaram — the iconic South Indian temple wind instrument. One of the finest recordings of this rare instrument from the Films Division of India archives.',
                    type: 'live', category: 'Carnatic Instrumental', language: 'Instrumental',
                    year: 1970, duration: '42 min', rating: 8.5,
                    videoUrl:     'https://archive.org/embed/NadaswaramClassical1970',
                    thumbnailUrl: 'https://archive.org/services/img/NadaswaramClassical1970',
                    featured: false, trending: false, status: 'published', views: 9500, likes: 8000
                }

            ]);
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
