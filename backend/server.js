require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// ========================================
// PORT CONFIGURATION
// ========================================
const PORT = process.env.PORT || 3000;
console.log('🚀 StreamIndia Backend Starting...');
console.log('📍 Port:', PORT);

// ========================================
// MIDDLEWARE - MUST BE BEFORE ROUTES
// ========================================
const allowedOrigins = [
    'https://streamindia-ott-platform.vercel.app',
    'https://streamindia-ott-platform-dgj8.vercel.app',
    'http://localhost:3000',
    'http://localhost:5173'
];

app.use(cors({
    origin: function(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

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
const JWT_SECRET = process.env.JWT_SECRET || 'streamindia-secret-2026';

console.log('🔧 MongoDB URI:', MONGODB_URI ? '✓ Set' : '✗ Missing');
console.log('🔧 JWT Secret:', JWT_SECRET ? '✓ Set' : '✗ Missing');

// ========================================
// MONGODB CONNECTION WITH CACHING (VERCEL OPTIMIZED)
// ========================================
let cached = global.mongoose;

if (!cached) {
    cached = global.mongoose = { conn: null, promise: null };
}

async function connectDB() {
    if (cached.conn) {
        console.log('✅ Using cached MongoDB connection');
        return cached.conn;
    }

    if (!MONGODB_URI) {
        throw new Error('MongoDB URI not configured');
    }

    if (!cached.promise) {
        const opts = {
            bufferCommands: false,
            maxPoolSize: 10,
            serverSelectionTimeoutMS: 10000,
            socketTimeoutMS: 45000,
            dbName: 'classicflims'  // ← COLLECTION NAME SET TO "classicflims"
        };

        console.log('🔄 Creating new MongoDB connection...');
        console.log('📊 Database: classicflims');
        
        cached.promise = mongoose.connect(MONGODB_URI, opts)
            .then((mongoose) => {
                console.log('✅ MongoDB Connected to database: classicflims');
                return mongoose;
            });
    }

    try {
        cached.conn = await cached.promise;
    } catch (e) {
        cached.promise = null;
        console.error('❌ MongoDB connection failed:', e.message);
        throw e;
    }

    return cached.conn;
}

// Connect on startup
if (MONGODB_URI) {
    connectDB().catch(err => console.error('❌ Initial connection failed:', err));
}

// ========================================
// SCHEMAS WITH EXPLICIT COLLECTION NAMES
// ========================================
const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'admin' },
    createdAt: { type: Date, default: Date.now }
}, { collection: 'admins' });  // Explicit collection name

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
}, { collection: 'contents' });

const navigationSchema = new mongoose.Schema({
    label: { type: String, required: true },
    url: { type: String, required: true },
    icon: String,
    order: { type: Number, default: 0 },
    active: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
}, { collection: 'navigations' });

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
}, { collection: 'advertisements' });

const settingsSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    value: mongoose.Schema.Types.Mixed,
    category: { type: String, default: 'general' },
    description: String,
    updatedAt: { type: Date, default: Date.now }
}, { collection: 'settings' });

// Models - Use mongoose.models to prevent recompilation in serverless
const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);
const Content = mongoose.models.Content || mongoose.model('Content', contentSchema);
const Navigation = mongoose.models.Navigation || mongoose.model('Navigation', navigationSchema);
const Advertisement = mongoose.models.Advertisement || mongoose.model('Advertisement', advertisementSchema);
const Settings = mongoose.models.Settings || mongoose.model('Settings', settingsSchema);

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
        message: 'StreamIndia Backend API',
        version: '1.0.0',
        status: 'running',
        database: 'classicflims',
        timestamp: new Date().toISOString(),
        endpoints: {
            health: '/health',
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
        database: {
            connected: mongoose.connection.readyState === 1,
            name: 'classicflims'
        },
        port: PORT
    });
});

// ========================================
// ADMIN AUTH - FIXED ROUTE PATH
// ========================================
app.get('/api/admin/login', (req, res) => {
    res.sendFile(__dirname + '/public/admin.html');
});

app.post('/api/admin/login, async (req, res) => {
    try {
        await connectDB();  // Ensure connection
        
        console.log('🔐 Login attempt:', req.body.username);
        
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        
        const admin = await Admin.findOne({ username });
        
        if (!admin) {
            console.log('❌ Admin not found');
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, admin.password);
        
        if (!validPassword) {
            console.log('❌ Invalid password');
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { id: admin._id, username: admin.username, role: admin.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        console.log('✅ Login successful');
        
        res.json({
            success: true,
            token,
            admin: {
                id: admin._id,
                username: admin.username,
                email: admin.email,
                role: admin.role
            }
        });
        
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// CONTENT ROUTES
// ========================================
app.get('/api/content', async (req, res) => {
    try {
        await connectDB();
        
        const { category, type, status, search, featured, trending, page = 1, limit = 20 } = req.query;
        const query = {};
        
        if (category) query.category = category;
        if (type) query.type = type;
        if (status) query.status = status;
        else query.status = 'published';
        if (featured === 'true') query.featured = true;
        if (trending === 'true') query.trending = true;
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
        await connectDB();
        
        const content = await Content.findById(req.params.id);
        if (!content) return res.status(404).json({ error: 'Content not found' });
        
        res.json(content);
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/content/:id/view', async (req, res) => {
    try {
        await connectDB();
        
        const content = await Content.findByIdAndUpdate(
            req.params.id,
            { $inc: { views: 1 } },
            { new: true }
        );
        
        if (!content) return res.status(404).json({ error: 'Content not found' });
        
        res.json({ views: content.views });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/content', authMiddleware, async (req, res) => {
    try {
        await connectDB();
        
        const content = await Content.create(req.body);
        res.status(201).json(content);
        
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/api/content/:id', authMiddleware, async (req, res) => {
    try {
        await connectDB();
        
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
        await connectDB();
        
        const content = await Content.findByIdAndDelete(req.params.id);
        if (!content) return res.status(404).json({ error: 'Content not found' });
        
        res.json({ message: 'Content deleted successfully' });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// NAVIGATION ROUTES
// ========================================
app.get('/api/navigation', async (req, res) => {
    try {
        await connectDB();
        
        const navigation = await Navigation.find({ active: true }).sort({ order: 1 });
        res.json(navigation);
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/navigation', authMiddleware, async (req, res) => {
    try {
        await connectDB();
        
        const navigation = await Navigation.create(req.body);
        res.status(201).json(navigation);
        
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/navigation/:id', authMiddleware, async (req, res) => {
    try {
        await connectDB();
        
        await Navigation.findByIdAndDelete(req.params.id);
        res.json({ message: 'Navigation deleted successfully' });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// ADVERTISEMENT ROUTES
// ========================================
app.get('/api/advertisements', async (req, res) => {
    try {
        await connectDB();
        
        const { position, type } = req.query;
        const query = { active: true };
        
        if (position) query.position = position;
        if (type) query.type = type;
        
        const ads = await Advertisement.find(query).sort({ priority: -1 });
        res.json(ads);
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/advertisements/:id/impression', async (req, res) => {
    try {
        await connectDB();
        
        await Advertisement.findByIdAndUpdate(
            req.params.id,
            { $inc: { impressions: 1 } }
        );
        
        res.json({ success: true });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/advertisements/:id/click', async (req, res) => {
    try {
        await connectDB();
        
        await Advertisement.findByIdAndUpdate(
            req.params.id,
            { $inc: { clicks: 1 } }
        );
        
        res.json({ success: true });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/advertisements', authMiddleware, async (req, res) => {
    try {
        await connectDB();
        
        const ad = await Advertisement.create(req.body);
        res.status(201).json(ad);
        
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/advertisements/:id', authMiddleware, async (req, res) => {
    try {
        await connectDB();
        
        await Advertisement.findByIdAndDelete(req.params.id);
        res.json({ message: 'Advertisement deleted successfully' });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// SETTINGS ROUTES
// ========================================
app.get('/api/settings', async (req, res) => {
    try {
        await connectDB();
        
        const settings = await Settings.find();
        
        // Convert to key-value object for easy frontend consumption
        const settingsObj = {};
        settings.forEach(setting => {
            settingsObj[setting.key] = setting.value;
        });
        
        res.json(settingsObj);
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/settings', authMiddleware, async (req, res) => {
    try {
        await connectDB();
        
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
        await connectDB();
        
        const totalContent = await Content.countDocuments();
        const publishedContent = await Content.countDocuments({ status: 'published' });
        const featuredContent = await Content.countDocuments({ featured: true });
        const trendingContent = await Content.countDocuments({ trending: true });
        
        const totalViews = await Content.aggregate([
            { $group: { _id: null, total: { $sum: '$views' } } }
        ]);
        
        const totalLikes = await Content.aggregate([
            { $group: { _id: null, total: { $sum: '$likes' } } }
        ]);
        
        res.json({
            totalContent,
            publishedContent,
            featuredContent,
            trendingContent,
            totalViews: totalViews[0]?.total || 0,
            totalLikes: totalLikes[0]?.total || 0
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// SEED ROUTE - INITIALIZE DATABASE
// ========================================
app.post('/api/seed', async (req, res) => {
    try {
        await connectDB();
        
        console.log('🌱 Starting database seed...');
        console.log('📊 Database: classicflims');
        
        // 1. Seed Admin
        const adminCount = await Admin.countDocuments();
        let adminCreated = false;
        
        if (adminCount === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            const admin = await Admin.create({
                username: 'admin',
                email: 'admin@streamindia.com',
                password: hashedPassword,
                role: 'admin'
            });
            console.log('✅ Admin created:', admin._id);
            adminCreated = true;
        } else {
            console.log('ℹ️ Admin already exists');
        }
        
        // 2. Seed Navigation
        const navCount = await Navigation.countDocuments();
        let navCreated = false;
        
        if (navCount === 0) {
            await Navigation.insertMany([
                { label: 'Home', url: '/', icon: '🏠', order: 1, active: true },
                { label: 'Movies', url: '/movies', icon: '🎬', order: 2, active: true },
                { label: 'Series', url: '/series', icon: '📺', order: 3, active: true },
                { label: 'Live', url: '/live', icon: '📡', order: 4, active: true },
                { label: 'Documentaries', url: '/documentaries', icon: '📽️', order: 5, active: true }
            ]);
            console.log('✅ Navigation items created');
            navCreated = true;
        }
        
        // 3. Seed Settings
        const settingsCount = await Settings.countDocuments();
        let settingsCreated = false;
        
        if (settingsCount === 0) {
            await Settings.insertMany([
                { key: 'site_name', value: 'StreamIndia', category: 'general', description: 'Website name' },
                { key: 'site_tagline', value: 'Premium Indian Content Streaming', category: 'general', description: 'Website tagline' },
                { key: 'primary_color', value: '#ff3366', category: 'theme', description: 'Primary brand color' },
                { key: 'secondary_color', value: '#7c3aed', category: 'theme', description: 'Secondary brand color' }
            ]);
            console.log('✅ Settings created');
            settingsCreated = true;
        }
        
        // 4. Seed Sample Content (optional)
        const contentCount = await Content.countDocuments();
        let contentCreated = false;
        
        if (contentCount === 0) {
            await Content.insertMany([
                {
                    title: 'Sample Movie 1',
                    description: 'A great Indian movie',
                    type: 'movie',
                    category: 'Drama',
                    language: 'Hindi',
                    year: 2024,
                    duration: '120 min',
                    rating: 8.5,
                    videoUrl: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
                    thumbnailUrl: 'https://picsum.photos/400/600?random=1',
                    featured: true,
                    trending: true,
                    status: 'published'
                },
                {
                    title: 'Sample Series 1',
                    description: 'An amazing series',
                    type: 'series',
                    category: 'Thriller',
                    language: 'Tamil',
                    year: 2024,
                    duration: '8 episodes',
                    rating: 8.0,
                    videoUrl: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
                    thumbnailUrl: 'https://picsum.photos/400/600?random=2',
                    featured: true,
                    trending: false,
                    status: 'published'
                }
            ]);
            console.log('✅ Sample content created');
            contentCreated = true;
        }
        
        // Verify data was saved
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const finalCounts = {
            admins: await Admin.countDocuments(),
            navigation: await Navigation.countDocuments(),
            settings: await Settings.countDocuments(),
            content: await Content.countDocuments()
        };
        
        res.json({
            success: true,
            message: 'Database seeded successfully',
            database: 'classicflims',
            created: {
                admin: adminCreated,
                navigation: navCreated,
                settings: settingsCreated,
                content: contentCreated
            },
            counts: finalCounts,
            credentials: {
                username: 'admin',
                password: 'admin123',
                note: 'Use these to login at /api/admin/login'
            }
        });
        
    } catch (error) {
        console.error('❌ Seed error:', error);
        res.status(500).json({ 
            success: false,
            error: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// ========================================
// 404 HANDLER - MUST BE LAST!
// ========================================
app.use((req, res) => {
    console.log('❌ 404 Not Found:', req.method, req.path);
    res.status(404).json({
        error: 'Route not found',
        path: req.path,
        method: req.method,
        message: 'This endpoint does not exist',
        availableEndpoints: [
            'GET /',
            'GET /health',
            'POST /api/admin/login',
            'GET /api/content',
            'POST /api/seed'
        ]
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
// ========================================
if (require.main === module) {
    app.listen(PORT, '0.0.0.0', () => {
        console.log('='.repeat(50));
        console.log('✅ SERVER STARTED SUCCESSFULLY!');
        console.log(`🚀 Listening on http://0.0.0.0:${PORT}`);
        console.log(`📍 API: http://0.0.0.0:${PORT}/api`);
        console.log(`📊 Database: classicflims`);
        console.log('='.repeat(50));
    });
}

// Export for Vercel
module.exports = app;
