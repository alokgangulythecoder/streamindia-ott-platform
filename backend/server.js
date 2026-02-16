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

// Logging middleware
app.use((req, res, next) => {
    console.log(`${req.method} ${req.path}`);
    next();
});

// ========================================
// ENVIRONMENT VARIABLES
// ========================================

const MONGODB_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'default-secret-change-me';

console.log('🔧 MongoDB URI:', MONGODB_URI ? '✓ Set' : '✗ Missing');
console.log('🔧 JWT Secret:', JWT_SECRET ? '✓ Set' : '✗ Missing');

// ========================================
// MONGODB CONNECTION
// ========================================

if (MONGODB_URI) {
    console.log('🔄 Connecting to MongoDB...');
    mongoose.connect(MONGODB_URI)
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

const Admin = mongoose.model('Admin', adminSchema);
const Content = mongoose.model('Content', contentSchema);
const Navigation = mongoose.model('Navigation', navigationSchema);
const Advertisement = mongoose.model('Advertisement', advertisementSchema);
const Settings = mongoose.model('Settings', settingsSchema);

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
        const { category, type, status, search, page = 1, limit = 20 } = req.query;
        const query = {};
        if (category) query.category = category;
        if (type) query.type = type;
        if (status) query.status = status;
        else query.status = 'published';
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
        const ads = await Advertisement.find({ active: true }).sort({ priority: -1 });
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

app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
    try {
        const totalContent = await Content.countDocuments();
        const publishedContent = await Content.countDocuments({ status: 'published' });
        const totalViews = await Content.aggregate([
            { $group: { _id: null, total: { $sum: '$views' } } }
        ]);
        const totalLikes = await Content.aggregate([
            { $group: { _id: null, total: { $sum: '$likes' } } }
        ]);
        
        res.json({
            totalContent,
            publishedContent,
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
        
        // Admin
        const adminCount = await Admin.countDocuments();
        if (adminCount === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await Admin.create({
                username: 'admin',
                email: 'admin@classicflims.com',
                password: hashedPassword,
                role: 'admin'
            });
            console.log('✅ Admin created');
        }
        
        // Navigation
        const navCount = await Navigation.countDocuments();
        if (navCount === 0) {
            await Navigation.insertMany([
                { label: 'Home', url: '/', icon: '🏠', order: 0, active: true },
                { label: 'Classic Films', url: '/classic-films', icon: '🎬', order: 1, active: true },
                { label: 'Film Noir', url: '/film-noir', icon: '🎭', order: 2, active: true },
                { label: 'Documentaries', url: '/documentaries', icon: '📽️', order: 3, active: true }
            ]);
            console.log('✅ Navigation created');
        }
        
        // Settings
        const settingsCount = await Settings.countDocuments();
        if (settingsCount === 0) {
            await Settings.insertMany([
                { key: 'site_name', value: 'ClassicFlims', category: 'general' },
                { key: 'site_tagline', value: 'Premium Classic Films', category: 'general' },
                { key: 'primary_color', value: '#1a1a1a', category: 'theme' },
                { key: 'secondary_color', value: '#d4af37', category: 'theme' }
            ]);
            console.log('✅ Settings created');
        }
        
        // Content
        const contentCount = await Content.countDocuments();
        if (contentCount === 0) {
            await Content.insertMany([
                {
                    title: 'Casablanca',
                    description: 'A cynical expatriate American cafe owner struggles to decide whether or not to help his former lover and her fugitive husband escape the Nazis in French Morocco.',
                    type: 'movie',
                    category: 'Classic Hollywood',
                    language: 'English',
                    year: 1942,
                    duration: '102 min',
                    rating: 8.5,
                    videoUrl: 'https://www.youtube.com/watch?v=BkL9l7qovsE',
                    thumbnailUrl: 'https://picsum.photos/400/600?random=10',
                    featured: true,
                    trending: true,
                    status: 'published',
                    views: 1250,
                    likes: 890
                },
                {
                    title: 'Citizen Kane',
                    description: 'Following the death of publishing tycoon Charles Foster Kane, reporters scramble to uncover the meaning of his final utterance.',
                    type: 'movie',
                    category: 'Classic Hollywood',
                    language: 'English',
                    year: 1941,
                    duration: '119 min',
                    rating: 8.3,
                    videoUrl: 'https://www.youtube.com/watch?v=zyREh-jWIEE',
                    thumbnailUrl: 'https://picsum.photos/400/600?random=11',
                    featured: true,
                    trending: false,
                    status: 'published',
                    views: 980,
                    likes: 765
                },
                {
                    title: 'The Maltese Falcon',
                    description: 'A San Francisco private detective takes on a case that involves three eccentric criminals and their quest for a priceless statuette.',
                    type: 'movie',
                    category: 'Film Noir',
                    language: 'English',
                    year: 1941,
                    duration: '100 min',
                    rating: 8.1,
                    videoUrl: 'https://www.youtube.com/watch?v=Q4g3BfL6RaE',
                    thumbnailUrl: 'https://picsum.photos/400/600?random=12',
                    featured: false,
                    trending: true,
                    status: 'published',
                    views: 670,
                    likes: 543
                }
            ]);
            console.log('✅ Content created');
        }
        
        res.json({ 
            message: 'Database seeded successfully',
            summary: {
                admins: 1,
                navigation: 4,
                settings: 4,
                content: 3
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
// START SERVER - CRITICAL FOR RAILWAY
// ========================================

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log('='.repeat(50));
    console.log('✅ SERVER STARTED SUCCESSFULLY!');
    console.log(`🚀 Listening on http://0.0.0.0:${PORT}`);
    console.log(`📍 API: http://0.0.0.0:${PORT}/api`);
    console.log(`🏥 Health: http://0.0.0.0:${PORT}/health`);
    console.log('='.repeat(50));
});

// Handle server errors
server.on('error', (error) => {
    console.error('❌ Server error:', error);
    if (error.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use`);
        process.exit(1);
    }
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    server.close(() => {
        console.log('Server closed');
        mongoose.connection.close(false, () => {
            console.log('MongoDB connection closed');
            process.exit(0);
        });
    });
});

module.exports = app;
