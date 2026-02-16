require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');

const app = express();

// Middleware
// CORS Configuration
app.options('*', cors());
app.use(cors());


app.use(express.json());

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Admin panel route
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Environment variables
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'streamindia-secret-key-change-in-production';
const MONGODB_URI = process.env.MONGO_URI || process.env.MONGO_URL;

// MongoDB Connection
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
    console.error('❌ MongoDB connection error:', error.message);
});

// ========================================
// ROUTES
// ========================================

// Root Route
app.get('/', (req, res) => {
    res.json({
        message: 'ClassicFlims Backend API',
        version: '1.0.0',
        status: 'running',
        tagline: 'Premium Classic Films & Timeless Cinema',
        endpoints: {
            admin: '/admin',
            api: '/api',
            health: '/health',
            seed: '/api/seed'
        }
    });
});

// Admin Panel Route (IMPORTANT!)
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Health Check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// ========================================
// SCHEMAS & MODELS
// ========================================

// Admin Schema
const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'admin' },
    createdAt: { type: Date, default: Date.now }
});

const Admin = mongoose.model('Admin', adminSchema);

// Content Schema
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

const Content = mongoose.model('Content', contentSchema);

// Navigation Schema
const navigationSchema = new mongoose.Schema({
    label: { type: String, required: true },
    url: { type: String, required: true },
    icon: String,
    order: { type: Number, default: 0 },
    active: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const Navigation = mongoose.model('Navigation', navigationSchema);

// Advertisement Schema
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

const Advertisement = mongoose.model('Advertisement', advertisementSchema);

// Settings Schema
const settingsSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    value: mongoose.Schema.Types.Mixed,
    category: { type: String, default: 'general' },
    description: String,
    updatedAt: { type: Date, default: Date.now }
});

const Settings = mongoose.model('Settings', settingsSchema);

// Analytics Schema
const analyticsSchema = new mongoose.Schema({
    contentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Content' },
    type: { type: String, enum: ['view', 'like', 'share'], required: true },
    userId: String,
    ipAddress: String,
    userAgent: String,
    timestamp: { type: Date, default: Date.now }
});

const Analytics = mongoose.model('Analytics', analyticsSchema);

// ========================================
// MIDDLEWARE
// ========================================

// Auth Middleware
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

// File Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// ========================================
// ROUTES
// ========================================

// Root Route
app.get('/', (req, res) => {
    res.json({
        message: 'ClassicFlims Backend API',
        version: '1.0.0',
        status: 'running',
        tagline: 'Premium Classic Films & Timeless Cinema',
        endpoints: {
            admin: '/admin',
            api: '/api',
            health: '/health',
            seed: '/api/seed'
        }
    });
});

// Health Check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// ========================================
// ADMIN AUTHENTICATION
// ========================================

// Admin Login
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

// Get all content
app.get('/api/content', async (req, res) => {
    try {
        const { category, type, status, search, page = 1, limit = 20 } = req.query;
        
        const query = {};
        if (category) query.category = category;
        if (type) query.type = type;
        if (status) query.status = status;
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

// Get single content
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

// Create content (Protected)
app.post('/api/content', authMiddleware, async (req, res) => {
    try {
        const content = await Content.create(req.body);
        res.status(201).json(content);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Update content (Protected)
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

// Delete content (Protected)
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

// Get content by category
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

// Search content
app.get('/api/content/search', async (req, res) => {
    try {
        const { q } = req.query;
        const content = await Content.find({
            $or: [
                { title: { $regex: q, $options: 'i' } },
                { description: { $regex: q, $options: 'i' } }
            ],
            status: 'published'
        }).limit(20);
        res.json(content);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// NAVIGATION ROUTES
// ========================================

// Get all navigation
app.get('/api/navigation', async (req, res) => {
    try {
        const navigation = await Navigation.find({ active: true }).sort({ order: 1 });
        res.json(navigation);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create navigation (Protected)
app.post('/api/navigation', authMiddleware, async (req, res) => {
    try {
        const navigation = await Navigation.create(req.body);
        res.status(201).json(navigation);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Update navigation (Protected)
app.put('/api/navigation/:id', authMiddleware, async (req, res) => {
    try {
        const navigation = await Navigation.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true }
        );
        if (!navigation) {
            return res.status(404).json({ error: 'Navigation not found' });
        }
        res.json(navigation);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Delete navigation (Protected)
app.delete('/api/navigation/:id', authMiddleware, async (req, res) => {
    try {
        const navigation = await Navigation.findByIdAndDelete(req.params.id);
        if (!navigation) {
            return res.status(404).json({ error: 'Navigation not found' });
        }
        res.json({ message: 'Navigation deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// ADVERTISEMENT ROUTES
// ========================================

// Get all advertisements
app.get('/api/advertisements', async (req, res) => {
    try {
        const ads = await Advertisement.find({ active: true }).sort({ priority: -1 });
        res.json(ads);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create advertisement (Protected)
app.post('/api/advertisements', authMiddleware, async (req, res) => {
    try {
        const ad = await Advertisement.create(req.body);
        res.status(201).json(ad);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Update advertisement (Protected)
app.put('/api/advertisements/:id', authMiddleware, async (req, res) => {
    try {
        const ad = await Advertisement.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true }
        );
        if (!ad) {
            return res.status(404).json({ error: 'Advertisement not found' });
        }
        res.json(ad);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Delete advertisement (Protected)
app.delete('/api/advertisements/:id', authMiddleware, async (req, res) => {
    try {
        const ad = await Advertisement.findByIdAndDelete(req.params.id);
        if (!ad) {
            return res.status(404).json({ error: 'Advertisement not found' });
        }
        res.json({ message: 'Advertisement deleted successfully' });
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
        res.json(settings);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get single setting
app.get('/api/settings/:key', async (req, res) => {
    try {
        const setting = await Settings.findOne({ key: req.params.key });
        if (!setting) {
            return res.status(404).json({ error: 'Setting not found' });
        }
        res.json(setting);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create or Update setting (Protected)
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

// Delete setting (Protected)
app.delete('/api/settings/:id', authMiddleware, async (req, res) => {
    try {
        const setting = await Settings.findByIdAndDelete(req.params.id);
        if (!setting) {
            return res.status(404).json({ error: 'Setting not found' });
        }
        res.json({ message: 'Setting deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================================
// ANALYTICS ROUTES
// ========================================

// Track view
app.post('/api/analytics/view', async (req, res) => {
    try {
        const { contentId } = req.body;
        
        // Create analytics record
        await Analytics.create({
            contentId,
            type: 'view',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent']
        });
        
        // Increment content views
        await Content.findByIdAndUpdate(contentId, { $inc: { views: 1 } });
        
        res.json({ message: 'View tracked' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Track like
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

// ========================================
// SEED DATA (Development Only)
// ========================================

app.post('/api/seed', async (req, res) => {
    try {
        console.log('🌱 Starting database seed...');
        
        // 1. Create admin user
        const adminCount = await Admin.countDocuments();
        if (adminCount === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await Admin.create({
                username: 'admin',
                email: 'admin@classicflims.com',
                password: hashedPassword,
                role: 'admin'
            });
            console.log('✅ Admin user created');
        }
        
        // 2. Create Navigation items
        const navCount = await Navigation.countDocuments();
        if (navCount === 0) {
            const navigationItems = [
                { label: 'Home', url: '/', icon: '🏠', order: 0, active: true },
                { label: 'Classic Films', url: '/classic-films', icon: '🎬', order: 1, active: true },
                { label: 'Golden Age', url: '/golden-age', icon: '🌟', order: 2, active: true },
                { label: 'Film Noir', url: '/film-noir', icon: '🎭', order: 3, active: true },
                { label: 'Documentaries', url: '/documentaries', icon: '📽️', order: 4, active: true },
                { label: 'Silent Films', url: '/silent-films', icon: '🎪', order: 5, active: true }
            ];
            await Navigation.insertMany(navigationItems);
            console.log('✅ Navigation items created (6)');
        }
        
        // 3. Create Advertisements
        const adCount = await Advertisement.countDocuments();
        if (adCount === 0) {
            const advertisements = [
                {
                    title: 'Premium Banner - Casablanca Special',
                    type: 'banner',
                    position: 'header',
                    imageUrl: 'https://picsum.photos/1200/200?random=1',
                    clickUrl: 'https://classicflims.netlify.app/casablanca',
                    priority: 10,
                    active: true
                },
                {
                    title: 'Sidebar - Film Noir Collection',
                    type: 'banner',
                    position: 'sidebar',
                    imageUrl: 'https://picsum.photos/300/600?random=2',
                    clickUrl: 'https://classicflims.netlify.app/film-noir',
                    priority: 8,
                    active: true
                },
                {
                    title: 'Footer Banner - Subscribe Now',
                    type: 'banner',
                    position: 'footer',
                    imageUrl: 'https://picsum.photos/1200/100?random=3',
                    clickUrl: 'https://classicflims.netlify.app/subscribe',
                    priority: 6,
                    active: true
                },
                {
                    title: 'Video Ad - Classic Movie Trailers',
                    type: 'video',
                    position: 'player',
                    imageUrl: 'https://picsum.photos/800/450?random=4',
                    clickUrl: 'https://classicflims.netlify.app',
                    priority: 9,
                    active: true
                },
                {
                    title: 'Popup - Weekend Special Offer',
                    type: 'popup',
                    position: 'header',
                    imageUrl: 'https://picsum.photos/600/400?random=5',
                    clickUrl: 'https://classicflims.netlify.app/offers',
                    priority: 7,
                    active: false
                }
            ];
            await Advertisement.insertMany(advertisements);
            console.log('✅ Advertisements created (5)');
        }
        
        // 4. Create Settings
        const settingsCount = await Settings.countDocuments();
        if (settingsCount === 0) {
            const defaultSettings = [
                { key: 'site_name', value: 'ClassicFlims', category: 'general', description: 'Website name' },
                { key: 'site_tagline', value: 'Premium Classic Films & Timeless Cinema', category: 'general', description: 'Website tagline' },
                { key: 'primary_color', value: '#1a1a1a', category: 'theme', description: 'Primary theme color (Noir Black)' },
                { key: 'secondary_color', value: '#d4af37', category: 'theme', description: 'Secondary theme color (Vintage Gold)' },
                { key: 'accent_color', value: '#8b7355', category: 'theme', description: 'Accent theme color (Warm Sepia)' },
                { key: 'enable_ads', value: true, category: 'monetization', description: 'Enable advertisements' },
                { key: 'subscription_enabled', value: true, category: 'monetization', description: 'Enable subscription feature' },
                { key: 'app_version', value: '1.0.0', category: 'app', description: 'Current app version' },
                { key: 'maintenance_mode', value: false, category: 'general', description: 'Enable maintenance mode' }
            ];
            await Settings.insertMany(defaultSettings);
            console.log('✅ Settings created (9)');
        }
        
        // 5. Create Sample Content
        const contentCount = await Content.countDocuments();
        if (contentCount === 0) {
            const sampleContent = [
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
                    description: 'San Francisco private detective Sam Spade takes on a case that involves him with three eccentric criminals, a gorgeous liar, and their quest for a priceless statuette.',
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
                    description: 'An insurance representative lets himself be talked into a murder/insurance fraud scheme that arouses an insurance investigator\'s suspicions.',
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
                    description: 'Dorothy Gale is swept away from a farm in Kansas to a magical land of Oz in a tornado and embarks on a quest with her new friends to see the Wizard who can help her return home.',
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
            ];
            await Content.insertMany(sampleContent);
            console.log('✅ Sample content created (6 classic films)');
        }
        
        console.log('🎉 Database seed completed successfully!');
        
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
// DASHBOARD STATS (Protected)
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
// ERROR HANDLING
// ========================================

// 404 Handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Error Handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal server error' });
});

// ========================================
// START SERVER
// ========================================

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 Admin Panel: http://localhost:${PORT}/admin`);
    console.log(`🔗 API: http://localhost:${PORT}/api`);
});

module.exports = app;
