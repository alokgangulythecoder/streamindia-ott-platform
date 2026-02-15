// server.js - Main Backend Server with Admin Panel
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));

// Configuration
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'streamindia-secret-key-change-in-production';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/streamindia';

// MongoDB Connection
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('✅ Connected to MongoDB');
}).catch(err => {
    console.error('❌ MongoDB connection error:', err);
});

// ========================================
// SCHEMAS & MODELS
// ========================================

// Admin User Schema
const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'editor', 'viewer'], default: 'admin' },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date }
});

const Admin = mongoose.model('Admin', adminSchema);

// Content Schema
const contentSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    type: { type: String, enum: ['movie', 'series', 'video', 'live'], required: true },
    category: { type: String, required: true },
    language: { type: String },
    year: { type: Number },
    duration: { type: String },
    rating: { type: Number, min: 0, max: 10 },
    badge: { type: String },
    genre: { type: String },
    thumbnail: { type: String },
    poster: { type: String },
    videoUrl: { type: String },
    trailerUrl: { type: String },
    cast: [{ type: String }],
    director: { type: String },
    tags: [{ type: String }],
    featured: { type: Boolean, default: false },
    trending: { type: Boolean, default: false },
    status: { type: String, enum: ['draft', 'published', 'archived'], default: 'published' },
    views: { type: Number, default: 0 },
    likes: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Content = mongoose.model('Content', contentSchema);

// Navigation Menu Schema
const navigationSchema = new mongoose.Schema({
    label: { type: String, required: true },
    url: { type: String },
    order: { type: Number, default: 0 },
    parent: { type: mongoose.Schema.Types.ObjectId, ref: 'Navigation' },
    active: { type: Boolean, default: true },
    icon: { type: String }
});

const Navigation = mongoose.model('Navigation', navigationSchema);

// Advertisement Schema
const advertisementSchema = new mongoose.Schema({
    title: { type: String, required: true },
    type: { type: String, enum: ['banner', 'video', 'popup', 'sidebar'], required: true },
    position: { type: String, enum: ['header', 'footer', 'sidebar', 'content', 'modal'], required: true },
    imageUrl: { type: String },
    videoUrl: { type: String },
    clickUrl: { type: String },
    duration: { type: Number }, // For video ads (in seconds)
    skipAfter: { type: Number }, // Seconds before skip button appears
    startDate: { type: Date },
    endDate: { type: Date },
    active: { type: Boolean, default: true },
    impressions: { type: Number, default: 0 },
    clicks: { type: Number, default: 0 },
    priority: { type: Number, default: 0 }
});

const Advertisement = mongoose.model('Advertisement', advertisementSchema);

// Settings Schema
const settingsSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    value: { type: mongoose.Schema.Types.Mixed },
    category: { type: String },
    description: { type: String },
    updatedAt: { type: Date, default: Date.now }
});

const Settings = mongoose.model('Settings', settingsSchema);

// ========================================
// FILE UPLOAD CONFIGURATION
// ========================================

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = 'uploads/';
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|mp4|webm|avi/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only images and videos allowed.'));
        }
    }
});

// ========================================
// AUTHENTICATION MIDDLEWARE
// ========================================

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

// ========================================
// ADMIN AUTHENTICATION ROUTES
// ========================================

// Register Admin (First time setup)
app.post('/api/admin/register', async (req, res) => {
    try {
        const { username, email, password, role } = req.body;

        // Check if admin already exists
        const existingAdmin = await Admin.findOne({ $or: [{ username }, { email }] });
        if (existingAdmin) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create admin
        const admin = new Admin({
            username,
            email,
            password: hashedPassword,
            role: role || 'admin'
        });

        await admin.save();

        res.status(201).json({ 
            message: 'Admin created successfully',
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

// Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find admin
        const admin = await Admin.findOne({ username });
        if (!admin) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        admin.lastLogin = new Date();
        await admin.save();

        // Generate JWT
        const token = jwt.sign(
            { id: admin._id, username: admin.username, role: admin.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            admin: {
                id: admin._id,
                username: admin.username,
                email: admin.email,
                role: admin.role,
                lastLogin: admin.lastLogin
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// CONTENT MANAGEMENT ROUTES
// ========================================

// Get all content (with filters)
app.get('/api/content', async (req, res) => {
    try {
        const { 
            type, category, language, status, 
            featured, trending, search, 
            limit = 50, page = 1 
        } = req.query;

        const query = {};
        if (type) query.type = type;
        if (category) query.category = category;
        if (language) query.language = language;
        if (status) query.status = status;
        if (featured !== undefined) query.featured = featured === 'true';
        if (trending !== undefined) query.trending = trending === 'true';
        if (search) {
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } },
                { tags: { $in: [new RegExp(search, 'i')] } }
            ];
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);
        
        const content = await Content.find(query)
            .sort({ createdAt: -1 })
            .limit(parseInt(limit))
            .skip(skip);

        const total = await Content.countDocuments(query);

        res.json({
            content,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / parseInt(limit))
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get single content by ID
app.get('/api/content/:id', async (req, res) => {
    try {
        const content = await Content.findById(req.params.id);
        if (!content) {
            return res.status(404).json({ error: 'Content not found' });
        }
        res.json(content);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create new content (Admin only)
app.post('/api/content', authenticateToken, upload.fields([
    { name: 'thumbnail', maxCount: 1 },
    { name: 'poster', maxCount: 1 }
]), async (req, res) => {
    try {
        const contentData = { ...req.body };
        
        if (req.files) {
            if (req.files.thumbnail) {
                contentData.thumbnail = '/uploads/' + req.files.thumbnail[0].filename;
            }
            if (req.files.poster) {
                contentData.poster = '/uploads/' + req.files.poster[0].filename;
            }
        }

        // Parse arrays from string
        if (contentData.cast && typeof contentData.cast === 'string') {
            contentData.cast = JSON.parse(contentData.cast);
        }
        if (contentData.tags && typeof contentData.tags === 'string') {
            contentData.tags = JSON.parse(contentData.tags);
        }

        const content = new Content(contentData);
        await content.save();

        res.status(201).json({
            message: 'Content created successfully',
            content
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update content (Admin only)
app.put('/api/content/:id', authenticateToken, upload.fields([
    { name: 'thumbnail', maxCount: 1 },
    { name: 'poster', maxCount: 1 }
]), async (req, res) => {
    try {
        const contentData = { ...req.body };
        contentData.updatedAt = new Date();
        
        if (req.files) {
            if (req.files.thumbnail) {
                contentData.thumbnail = '/uploads/' + req.files.thumbnail[0].filename;
            }
            if (req.files.poster) {
                contentData.poster = '/uploads/' + req.files.poster[0].filename;
            }
        }

        // Parse arrays from string
        if (contentData.cast && typeof contentData.cast === 'string') {
            contentData.cast = JSON.parse(contentData.cast);
        }
        if (contentData.tags && typeof contentData.tags === 'string') {
            contentData.tags = JSON.parse(contentData.tags);
        }

        const content = await Content.findByIdAndUpdate(
            req.params.id,
            contentData,
            { new: true, runValidators: true }
        );

        if (!content) {
            return res.status(404).json({ error: 'Content not found' });
        }

        res.json({
            message: 'Content updated successfully',
            content
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete content (Admin only)
app.delete('/api/content/:id', authenticateToken, async (req, res) => {
    try {
        const content = await Content.findByIdAndDelete(req.params.id);
        if (!content) {
            return res.status(404).json({ error: 'Content not found' });
        }

        res.json({ message: 'Content deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Increment views
app.post('/api/content/:id/view', async (req, res) => {
    try {
        const content = await Content.findByIdAndUpdate(
            req.params.id,
            { $inc: { views: 1 } },
            { new: true }
        );
        res.json({ views: content.views });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// NAVIGATION MANAGEMENT ROUTES
// ========================================

// Get all navigation items
app.get('/api/navigation', async (req, res) => {
    try {
        const navigation = await Navigation.find({ active: true })
            .sort({ order: 1 })
            .populate('parent');
        res.json(navigation);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create navigation item (Admin only)
app.post('/api/navigation', authenticateToken, async (req, res) => {
    try {
        const navigation = new Navigation(req.body);
        await navigation.save();
        res.status(201).json(navigation);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update navigation item (Admin only)
app.put('/api/navigation/:id', authenticateToken, async (req, res) => {
    try {
        const navigation = await Navigation.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true }
        );
        res.json(navigation);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete navigation item (Admin only)
app.delete('/api/navigation/:id', authenticateToken, async (req, res) => {
    try {
        await Navigation.findByIdAndDelete(req.params.id);
        res.json({ message: 'Navigation item deleted' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// ADVERTISEMENT ROUTES
// ========================================

// Get active advertisements
app.get('/api/advertisements', async (req, res) => {
    try {
        const { position, type } = req.query;
        const query = { 
            active: true,
            $or: [
                { startDate: { $lte: new Date() }, endDate: { $gte: new Date() } },
                { startDate: null, endDate: null }
            ]
        };
        
        if (position) query.position = position;
        if (type) query.type = type;

        const ads = await Advertisement.find(query).sort({ priority: -1 });
        res.json(ads);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create advertisement (Admin only)
app.post('/api/advertisements', authenticateToken, upload.fields([
    { name: 'image', maxCount: 1 },
    { name: 'video', maxCount: 1 }
]), async (req, res) => {
    try {
        const adData = { ...req.body };
        
        if (req.files) {
            if (req.files.image) {
                adData.imageUrl = '/uploads/' + req.files.image[0].filename;
            }
            if (req.files.video) {
                adData.videoUrl = '/uploads/' + req.files.video[0].filename;
            }
        }

        const ad = new Advertisement(adData);
        await ad.save();
        res.status(201).json(ad);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Track ad impression
app.post('/api/advertisements/:id/impression', async (req, res) => {
    try {
        await Advertisement.findByIdAndUpdate(
            req.params.id,
            { $inc: { impressions: 1 } }
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Track ad click
app.post('/api/advertisements/:id/click', async (req, res) => {
    try {
        await Advertisement.findByIdAndUpdate(
            req.params.id,
            { $inc: { clicks: 1 } }
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// SETTINGS ROUTES
// ========================================

// Get all settings
app.get('/api/settings', async (req, res) => {
    try {
        const settings = await Settings.find();
        const settingsObj = {};
        settings.forEach(setting => {
            settingsObj[setting.key] = setting.value;
        });
        res.json(settingsObj);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update setting (Admin only)
app.put('/api/settings/:key', authenticateToken, async (req, res) => {
    try {
        const setting = await Settings.findOneAndUpdate(
            { key: req.params.key },
            { value: req.body.value, updatedAt: new Date() },
            { upsert: true, new: true }
        );
        res.json(setting);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// ANALYTICS ROUTES
// ========================================

// Get dashboard stats (Admin only)
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
        const totalContent = await Content.countDocuments();
        const publishedContent = await Content.countDocuments({ status: 'published' });
        const totalViews = await Content.aggregate([
            { $group: { _id: null, total: { $sum: '$views' } } }
        ]);
        const totalAds = await Advertisement.countDocuments({ active: true });

        const recentContent = await Content.find()
            .sort({ createdAt: -1 })
            .limit(10)
            .select('title type createdAt views');

        res.json({
            totalContent,
            publishedContent,
            totalViews: totalViews[0]?.total || 0,
            totalAds,
            recentContent
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// SEED DATA (Development Only)
// ========================================

app.post('/api/seed', async (req, res) => {
    try {
        // Create default admin if none exists
        const adminCount = await Admin.countDocuments();
        if (adminCount === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await Admin.create({
                username: 'admin',
                email: 'admin@streamindia.com',
                password: hashedPassword,
                role: 'admin'
            });
        }

        // Create default settings
        const defaultSettings = [
            { key: 'site_name', value: 'StreamIndia', category: 'general' },
            { key: 'site_tagline', value: 'Premium Entertainment Platform', category: 'general' },
            { key: 'primary_color', value: '#ff3366', category: 'theme' },
            { key: 'secondary_color', value: '#7c3aed', category: 'theme' },
            { key: 'enable_ads', value: true, category: 'monetization' },
            { key: 'subscription_enabled', value: true, category: 'monetization' }
        ];

        for (const setting of defaultSettings) {
            await Settings.findOneAndUpdate(
                { key: setting.key },
                setting,
                { upsert: true }
            );
        }

        res.json({ message: 'Database seeded successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// ROOT & ADMIN ROUTES
// ========================================

// Root route
app.get('/', (req, res) => {
    res.json({
        message: 'ClassicFlims Backend API',
        version: '1.0.0',
        status: 'running',
        tagline: 'Premium Classical Content Platform',
        endpoints: {
            admin: '/admin',
            api: '/api',
            health: '/health',
            seed: '/api/seed'
        }
    });
});

// Admin panel route
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ========================================
// START SERVER
// ========================================

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📊 Admin Panel: http://localhost:${PORT}/admin`);
    console.log(`🎬 Frontend: http://localhost:${PORT}`);
});

module.exports = app;
