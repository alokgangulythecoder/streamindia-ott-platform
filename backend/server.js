require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();

// ========================================
// ENVIRONMENT VARIABLES
// ========================================

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'classicflims-secret-2025';
const FRONTEND_URL = process.env.FRONTEND_URL || '*';

console.log('🚀 Starting ClassicFlims Backend...');
console.log('📍 Port:', PORT);
console.log('🌐 Frontend URL:', FRONTEND_URL);

// ========================================
// MIDDLEWARE
// ========================================

// CORS - Allow frontend to access backend
app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);
        
        // Allow all Railway URLs and your frontend
        if (
            origin.includes('railway.app') || 
            origin.includes('netlify.app') ||
            origin.includes('localhost') ||
            origin === FRONTEND_URL
        ) {
            return callback(null, true);
        }
        
        // Allow all origins in development
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (admin panel)
app.use(express.static(path.join(__dirname, 'public')));

// Request logging
app.use((req, res, next) => {
    console.log(`${req.method} ${req.path}`);
    next();
});

// ========================================
// MONGODB CONNECTION
// ========================================

if (!MONGODB_URI) {
    console.error('❌ MONGODB_URI environment variable is not set!');
    console.error('Please set it in Railway dashboard');
    process.exit(1);
}

console.log('🔄 Connecting to MongoDB...');

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('✅ Connected to MongoDB');
    console.log('📊 Database:', mongoose.connection.name);
})
.catch((error) => {
    console.error('❌ MongoDB connection failed!');
    console.error('Error:', error.message);
    process.exit(1);
});

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

const analyticsSchema = new mongoose.Schema({
    contentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Content' },
    type: { type: String, enum: ['view', 'like', 'share'], required: true },
    userId: String,
    ipAddress: String,
    userAgent: String,
    timestamp: { type: Date, default: Date.now }
});

const Admin = mongoose.model('Admin', adminSchema);
const Content = mongoose.model('Content', contentSchema);
const Navigation = mongoose.model('Navigation', navigationSchema);
const Advertisement = mongoose.model('Advertisement', advertisementSchema);
const Settings = mongoose.model('Settings', settingsSchema);
const Analytics = mongoose.model('Analytics', analyticsSchema);

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
// ROOT ROUTES
// ========================================

app.get('/', (req, res) => {
    res.json({
        message: 'ClassicFlims Backend API',
        version: '1.0.0',
        status: 'running',
        tagline: 'Premium Classic Films & Timeless Cinema',
        timestamp: new Date().toISOString(),
        endpoints: {
            root: '/',
            health: '/health',
            admin_panel: '/admin',
            api_base: '/api',
            seed: '/api/seed',
            content: '/api/content',
            navigation: '/api/navigation',
            advertisements: '/api/advertisements',
            settings: '/api/settings'
        }
    });
});

app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        environment: process.env.NODE_ENV || 'development'
    });
});

// Admin Panel Route
app.get('/admin', (req, res) => {
    const adminPath = path.join(__dirname, 'public', 'admin.html');
    res.sendFile(adminPath, (err) => {
        if (err) {
            console.error('Error sending admin.html:', err);
            res.status(404).json({ 
                error: 'Admin panel not found',
                message: 'Make sure admin.html exists in backend/public/ folder'
            });
        }
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
        else query.status = 'published'; // Default to published only
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
        if (!content) {
            return res.status(404).json({ error: 'Content not found' });
        }
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
        if (!content) {
            return res.status(404).json({ error: 'Content not found' });
        }
        res.json(content);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/content/:id', authMiddleware, async (req, res) => {
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

app.get('/api/content/category/:category', async (req, res) => {
    try {
        const content = await Content.find({ 
            category: req.params.category,
            status: 'published'
        }).sort({ createdAt: -1 });
        res.json(content);
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
        const navigation = await Navigation.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!navigation) return res.status(404).json({ error: 'Navigation not found' });
        res.json(navigation);
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

app.get('/api/settings/:key', async (req, res) => {
    try {
        const setting = await Settings.findOne({ key: req.params.key });
        if (!setting) return res.status(404).json({ error: 'Setting not found' });
        res.json(setting);
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

app.delete('/api/settings/:id', authMiddleware, async (req, res) => {
    try {
        await Settings.findByIdAndDelete(req.params.id);
        res.json({ message: 'Setting deleted' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// ANALYTICS
// ========================================

app.post('/api/analytics/view', async (req, res) => {
    try {
        const { contentId } = req.body;
        await Analytics.create({
            contentId,
            type: 'view',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent']
        });
        await Content.findByIdAndUpdate(contentId, { $inc: { views: 1 } });
        res.json({ message: 'View tracked' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/analytics/like', async (req, res) => {
    try {
        const { contentId } = req.body;
        await Analytics.create({
            contentId,
            type: 'like',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent']
        });
        await Content.findByIdAndUpdate(contentId, { $inc: { likes: 1 } });
        res.json({ message: 'Like tracked' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

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
        console.log('🌱 Starting database seed...');
        
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
                { label: 'Golden Age', url: '/golden-age', icon: '🌟', order: 2, active: true },
                { label: 'Film Noir', url: '/film-noir', icon: '🎭', order: 3, active: true },
                { label: 'Documentaries', url: '/documentaries', icon: '📽️', order: 4, active: true },
                { label: 'Silent Films', url: '/silent-films', icon: '🎪', order: 5, active: true }
            ]);
            console.log('✅ Navigation created (6)');
        }
        
        // Settings
        const settingsCount = await Settings.countDocuments();
        if (settingsCount === 0) {
            await Settings.insertMany([
                { key: 'site_name', value: 'ClassicFlims', category: 'general' },
                { key: 'site_tagline', value: 'Premium Classic Films & Timeless Cinema', category: 'general' },
                { key: 'primary_color', value: '#1a1a1a', category: 'theme' },
                { key: 'secondary_color', value: '#d4af37', category: 'theme' },
                { key: 'accent_color', value: '#8b7355', category: 'theme' },
                { key: 'enable_ads', value: true, category: 'monetization' },
                { key: 'subscription_enabled', value: true, category: 'monetization' },
                { key: 'app_version', value: '1.0.0', category: 'app' },
                { key: 'maintenance_mode', value: false, category: 'general' }
            ]);
            console.log('✅ Settings created (9)');
        }
        
        // Advertisements
        const adCount = await Advertisement.countDocuments();
        if (adCount === 0) {
            await Advertisement.insertMany([
                { title: 'Header Banner', type: 'banner', position: 'header', imageUrl: 'https://picsum.photos/1200/200?random=1', clickUrl: 'https://classicflims.up.railway.app', priority: 10, active: true },
                { title: 'Sidebar Ad', type: 'banner', position: 'sidebar', imageUrl: 'https://picsum.photos/300/600?random=2', clickUrl: 'https://classicflims.up.railway.app', priority: 8, active: true },
                { title: 'Footer Banner', type: 'banner', position: 'footer', imageUrl: 'https://picsum.photos/1200/100?random=3', clickUrl: 'https://classicflims.up.railway.app', priority: 6, active: true },
                { title: 'Video Ad', type: 'video', position: 'player', imageUrl: 'https://picsum.photos/800/450?random=4', clickUrl: 'https://classicflims.up.railway.app', priority: 9, active: true },
                { title: 'Popup Ad', type: 'popup', position: 'header', imageUrl: 'https://picsum.photos/600/400?random=5', clickUrl: 'https://classicflims.up.railway.app', priority: 7, active: false }
            ]);
            console.log('✅ Ads created (5)');
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
                    description: 'Following the death of publishing tycoon Charles Foster Kane, reporters scramble to uncover the meaning of his final utterance: Rosebud.',
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
                    description: 'San Francisco private detective Sam Spade takes on a case that involves him with three eccentric criminals and their quest for a priceless statuette.',
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
                },
                {
                    title: 'Double Indemnity',
                    description: 'An insurance representative lets himself be talked into a murder/insurance fraud scheme that arouses suspicions.',
                    type: 'movie',
                    category: 'Film Noir',
                    language: 'English',
                    year: 1944,
                    duration: '107 min',
                    rating: 8.3,
                    videoUrl: 'https://www.youtube.com/watch?v=S0z-F7BnqXA',
                    thumbnailUrl: 'https://picsum.photos/400/600?random=13',
                    featured: true,
                    trending: false,
                    status: 'published',
                    views: 820,
                    likes: 691
                },
                {
                    title: 'The Wizard of Oz',
                    description: 'Dorothy Gale is swept away from Kansas to a magical land of Oz and embarks on a quest with her new friends.',
                    type: 'movie',
                    category: 'Classic Hollywood',
                    language: 'English',
                    year: 1939,
                    duration: '102 min',
                    rating: 8.1,
                    videoUrl: 'https://www.youtube.com/watch?v=PSZxmZmBfnU',
                    thumbnailUrl: 'https://picsum.photos/400/600?random=14',
                    featured: false,
                    trending: true,
                    status: 'published',
                    views: 1540,
                    likes: 1230
                },
                {
                    title: 'Sunset Boulevard',
                    description: 'A screenwriter develops a dangerous relationship with a faded film star determined to make a triumphant return.',
                    type: 'movie',
                    category: 'Film Noir',
                    language: 'English',
                    year: 1950,
                    duration: '110 min',
                    rating: 8.4,
                    videoUrl: 'https://www.youtube.com/watch?v=wKRBj3-TszI',
                    thumbnailUrl: 'https://picsum.photos/400/600?random=15',
                    featured: true,
                    trending: true,
                    status: 'published',
                    views: 750,
                    likes: 612
                }
            ]);
            console.log('✅ Content created (6)');
        }
        
        res.json({ 
            message: 'Database seeded successfully',
            summary: {
                admins: 1,
                navigation: 6,
                advertisements: 5,
                settings: 9,
                content: 6
            }
        });
    } catch (error) {
        console.error('❌ Seed error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// ERROR HANDLERS
// ========================================

app.use((req, res) => {
    res.status(404).json({ 
        error: 'Route not found',
        path: req.path,
        message: 'The requested endpoint does not exist'
    });
});

app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ 
        error: 'Internal server error',
        message: err.message 
    });
});

// ========================================
// START SERVER
// ========================================

app.listen(PORT, '0.0.0.0', () => {
    console.log('✅ Server started successfully!');
    console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
    console.log(`📍 Admin Panel: http://0.0.0.0:${PORT}/admin`);
    console.log(`📍 API: http://0.0.0.0:${PORT}/api`);
    console.log('🎬 ClassicFlims Backend Ready!');
});

module.exports = app;
