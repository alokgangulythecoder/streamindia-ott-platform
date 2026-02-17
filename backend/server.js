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

const Admin = mongoose.model('Admin', adminSchema);
// ADD USER MODEL WITH OTHER MODELS
const User = mongoose.model('User', userSchema);
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
                // ===== MOVIES (10) =====
                { title: 'Awaara (1951)', description: "Raj Kapoor's iconic masterpiece. A poor vagabond Raj falls in love with Rita while his father — a harsh judge — believes criminals are born not made. One of the most-watched Indian films globally, a cult classic across USSR, China and Turkey.", type: 'movie', category: 'Classic Hindi', language: 'Hindi', year: 1951, duration: '168 min', rating: 8.0, videoUrl: 'https://archive.org/embed/awara-1951-raj-kapoor-nargis-classic-hindi-film', thumbnailUrl: 'https://archive.org/services/img/awara-1951-raj-kapoor-nargis-classic-hindi-film', featured: true, trending: true, status: 'published', views: 52000, likes: 41000 },
                { title: 'Shree 420 (1955)', description: "Raj Kapoor plays an innocent small-town man corrupted by Mumbai's greed. A sharp satire on capitalism with the legendary song 'Mera Joota Hai Japani'. Directed by Raj Kapoor.", type: 'movie', category: 'Classic Hindi', language: 'Hindi', year: 1955, duration: '168 min', rating: 7.8, videoUrl: 'https://archive.org/embed/shree-420-1955-raj-kapoor-nargis-classic-hindi-film', thumbnailUrl: 'https://archive.org/services/img/shree-420-1955-raj-kapoor-nargis-classic-hindi-film', featured: true, trending: false, status: 'published', views: 38000, likes: 29000 },
                { title: 'Jagte Raho (1956)', description: 'A thirsty villager sneaks into a Kolkata apartment building searching for water, witnessing the hypocrisy of city elites. Won the Crystal Globe at Karlovy Vary Film Festival.', type: 'movie', category: 'Classic Hindi', language: 'Hindi', year: 1956, duration: '155 min', rating: 7.9, videoUrl: 'https://archive.org/embed/jagte-raho-1956', thumbnailUrl: 'https://archive.org/services/img/jagte-raho-1956', featured: false, trending: true, status: 'published', views: 22000, likes: 17000 },
                { title: 'Do Bigha Zamin (1953)', description: "Bimal Roy's neo-realist landmark — a poor farmer travels to Calcutta to save his family land from a greedy zamindar. Won the International Critics Award at Cannes 1954.", type: 'movie', category: 'Classic Hindi', language: 'Hindi', year: 1953, duration: '142 min', rating: 8.2, videoUrl: 'https://archive.org/embed/DoBighaZamin1953', thumbnailUrl: 'https://archive.org/services/img/DoBighaZamin1953', featured: true, trending: false, status: 'published', views: 18500, likes: 15200 },
                { title: 'Pather Panchali (1955)', description: "Satyajit Ray's debut — the first of the Apu Trilogy. Young Apu grows up in rural Bengal with his dreamer father and mischievous sister Durga. Winner of Best Human Document at Cannes 1956.", type: 'movie', category: 'Bengali Classic', language: 'Bengali', year: 1955, duration: '125 min', rating: 8.5, videoUrl: 'https://archive.org/embed/pather-panchali-1955', thumbnailUrl: 'https://archive.org/services/img/pather-panchali-1955', featured: true, trending: true, status: 'published', views: 29000, likes: 24500 },
                { title: 'Aparajito (1956)', description: "Second of Satyajit Ray's Apu Trilogy. Apu moves to Varanasi and later Kolkata for education — a moving portrait of a son's independence and a mother's longing. Won the Golden Lion at Venice 1957.", type: 'movie', category: 'Bengali Classic', language: 'Bengali', year: 1956, duration: '110 min', rating: 8.3, videoUrl: 'https://archive.org/embed/aparajito-1956', thumbnailUrl: 'https://archive.org/services/img/aparajito-1956', featured: false, trending: false, status: 'published', views: 14000, likes: 11500 },
                { title: 'Chandralekha (1948)', description: "One of the most expensive Indian films of its era — a Tamil historical epic featuring the iconic 100-drummer sequence. Produced by S.S. Vasan, it was a massive pan-India blockbuster released in Tamil and Hindi.", type: 'movie', category: 'Tamil Classic', language: 'Tamil', year: 1948, duration: '200 min', rating: 7.4, videoUrl: 'https://archive.org/embed/Chandralekha1948TamilMovie', thumbnailUrl: 'https://archive.org/services/img/Chandralekha1948TamilMovie', featured: false, trending: true, status: 'published', views: 16200, likes: 12800 },
                { title: 'Parasakthi (1952)', description: "Sivaji Ganesan's debut — three brothers separated by Partition. Written by Karunanidhi, this politically charged Tamil drama transformed cinema and launched one of India's greatest acting careers.", type: 'movie', category: 'Tamil Classic', language: 'Tamil', year: 1952, duration: '170 min', rating: 8.0, videoUrl: 'https://archive.org/embed/Parasakthi1952', thumbnailUrl: 'https://archive.org/services/img/Parasakthi1952', featured: true, trending: false, status: 'published', views: 21000, likes: 17500 },
                { title: 'Pathala Bhairavi (1951)', description: 'A beloved Telugu fantasy — young Todu Ramudu faces the wicked magician Nepala Mantriki. Starring NT Rama Rao in a career-defining role. One of the greatest Telugu classics with stunning effects for its time.', type: 'movie', category: 'Telugu Classic', language: 'Telugu', year: 1951, duration: '175 min', rating: 7.9, videoUrl: 'https://archive.org/embed/PathaalaBhairavi1951TeluguMovie', thumbnailUrl: 'https://archive.org/services/img/PathaalaBhairavi1951TeluguMovie', featured: false, trending: true, status: 'published', views: 19800, likes: 15600 },
                { title: 'Neelakkuyil (1954)', description: 'A progressive Malayalam film addressing caste discrimination. Directed by P. Bhaskaran and Ramu Kariat — among the first realistic Malayalam films and a landmark in Kerala cinema history.', type: 'movie', category: 'Malayalam Classic', language: 'Malayalam', year: 1954, duration: '150 min', rating: 7.7, videoUrl: 'https://archive.org/embed/Neelakkuyil1954', thumbnailUrl: 'https://archive.org/services/img/Neelakkuyil1954', featured: true, trending: false, status: 'published', views: 13500, likes: 10800 },

                // ===== SERIES (10) =====
                { title: 'Ramayana (1987) — Episode 1', description: "Ramanand Sagar's iconic Doordarshan serial. Episode 1: The story begins in Ayodhya with King Dasharatha and the birth of Lord Rama. Holds the Guinness World Record for most-watched TV show.", type: 'series', category: 'Mythological', language: 'Hindi', year: 1987, duration: '45 min/ep', rating: 9.2, videoUrl: 'https://archive.org/embed/ramayana-1987-episode-1', thumbnailUrl: 'https://archive.org/services/img/ramayana-1987-episode-1', featured: true, trending: true, status: 'published', views: 89000, likes: 78000 },
                { title: 'Mahabharat (1988) — Episode 1', description: "B.R. Chopra's magnum opus. Episode 1 introduces the Kuru dynasty. With Mukesh Khanna as Bhishma and Nitish Bharadwaj as Krishna — this serial redefined Indian television.", type: 'series', category: 'Mythological', language: 'Hindi', year: 1988, duration: '45 min/ep', rating: 9.1, videoUrl: 'https://archive.org/embed/mahabharat-1988-episode-1', thumbnailUrl: 'https://archive.org/services/img/mahabharat-1988-episode-1', featured: true, trending: true, status: 'published', views: 76000, likes: 67000 },
                { title: 'Byomkesh Bakshi (1993)', description: "Doordarshan's beloved detective series. Rajit Kapur plays the 'truth-seeker' Byomkesh Bakshi in complex mysteries set in 1940s Kolkata. Acclaimed for its authentic period atmosphere.", type: 'series', category: 'Mystery Drama', language: 'Hindi', year: 1993, duration: '50 min/ep', rating: 8.7, videoUrl: 'https://archive.org/embed/ByomkeshBakshi1993Season1', thumbnailUrl: 'https://archive.org/services/img/ByomkeshBakshi1993Season1', featured: false, trending: true, status: 'published', views: 34000, likes: 28500 },
                { title: 'Malgudi Days (1987)', description: "Shankar Nag's timeless adaptation of R.K. Narayan's stories of the fictional South Indian town of Malgudi. Young Swami's charming adventures. The nostalgic theme by L. Subramaniam is forever etched in memory.", type: 'series', category: 'Family Drama', language: 'Hindi', year: 1987, duration: '25 min/ep', rating: 9.0, videoUrl: 'https://archive.org/embed/MalgudiDays1987Season1', thumbnailUrl: 'https://archive.org/services/img/MalgudiDays1987Season1', featured: true, trending: false, status: 'published', views: 41000, likes: 36500 },
                { title: 'Vikram aur Betaal (1985)', description: 'King Vikramaditya carries a corpse possessed by the spirit Betaal who tells a riddle story each episode. A beloved Doordarshan mythological-folk series that mesmerised a generation.', type: 'series', category: 'Mythology Folk', language: 'Hindi', year: 1985, duration: '25 min/ep', rating: 8.5, videoUrl: 'https://archive.org/embed/VikramaaurBetaal1985', thumbnailUrl: 'https://archive.org/services/img/VikramaaurBetaal1985', featured: false, trending: true, status: 'published', views: 27000, likes: 22000 },
                { title: 'Buniyaad (1986)', description: "India's most celebrated family saga — the Haveli Ram family from Partition 1947 to the 1980s. Directed by Ramesh Sippy. The first major prime-time serial on Doordarshan.", type: 'series', category: 'Family Saga', language: 'Hindi', year: 1986, duration: '50 min/ep', rating: 8.8, videoUrl: 'https://archive.org/embed/Buniyaad1986', thumbnailUrl: 'https://archive.org/services/img/Buniyaad1986', featured: true, trending: false, status: 'published', views: 31000, likes: 26000 },
                { title: 'Hum Log (1984)', description: "India's first soap opera — the Rastogi family's everyday struggles. 156 episodes, 50 million viewers per episode. Changed the landscape of Indian television forever.", type: 'series', category: 'Social Drama', language: 'Hindi', year: 1984, duration: '23 min/ep', rating: 8.3, videoUrl: 'https://archive.org/embed/HumLog1984', thumbnailUrl: 'https://archive.org/services/img/HumLog1984', featured: false, trending: false, status: 'published', views: 18000, likes: 14500 },
                { title: 'Tenali Rama (1988)', description: "The witty tales of Tenali Rama, the court jester of Emperor Krishnadevaraya. Each episode showcases clever solutions to impossible problems. A beloved Tamil/Telugu DD series introducing millions to South Indian folklore.", type: 'series', category: 'Historical Comedy', language: 'Tamil', year: 1988, duration: '25 min/ep', rating: 8.1, videoUrl: 'https://archive.org/embed/TenaliRama1988TamilSeries', thumbnailUrl: 'https://archive.org/services/img/TenaliRama1988TamilSeries', featured: false, trending: true, status: 'published', views: 23000, likes: 19000 },
                { title: 'Circus (1989)', description: "Shah Rukh Khan's television debut — a young trainee at a traveling circus discovers friendships and dreams. Directed by Aziz Mirza. The launch pad for the King of Bollywood.", type: 'series', category: 'Drama', language: 'Hindi', year: 1989, duration: '45 min/ep', rating: 8.4, videoUrl: 'https://archive.org/embed/Circus1989DoordarshantvsSerialShahrukhKhan', thumbnailUrl: 'https://archive.org/services/img/Circus1989DoordarshantvsSerialShahrukhKhan', featured: true, trending: true, status: 'published', views: 44000, likes: 38000 },
                { title: 'Nukkad (1986)', description: 'Ensemble drama about everyday lives of people gathered at a Delhi street corner. Two seasons of raw honesty, humor and empathy about urban Indian life. One of Doordarshan's most beloved series.', type: 'series', category: 'Social Drama', language: 'Hindi', year: 1986, duration: '25 min/ep', rating: 8.6, videoUrl: 'https://archive.org/embed/Nukkad1986Season1', thumbnailUrl: 'https://archive.org/services/img/Nukkad1986Season1', featured: false, trending: false, status: 'published', views: 19500, likes: 16200 },

                // ===== DOCUMENTARIES (10) =====
                { title: 'Gandhi — Archival Documentary (1962)', description: 'Rare archival footage of Mahatma Gandhi — speeches, the Salt March, the Independence movement. Features actual newsreel footage from British Pathé and Films Division of India.', type: 'documentary', category: 'Historical', language: 'English', year: 1962, duration: '62 min', rating: 8.9, videoUrl: 'https://archive.org/embed/gov.archives.arc.43754', thumbnailUrl: 'https://archive.org/services/img/gov.archives.arc.43754', featured: true, trending: false, status: 'published', views: 31000, likes: 26500 },
                { title: 'Night and Fog (1956)', description: "Alain Resnais' haunting documentary about Nazi concentration camps — alternating colour present-day footage with black-and-white archival film. One of the most powerful anti-war films ever made.", type: 'documentary', category: 'War History', language: 'French', year: 1956, duration: '32 min', rating: 8.6, videoUrl: 'https://archive.org/embed/NightAndFog1955', thumbnailUrl: 'https://archive.org/services/img/NightAndFog1955', featured: true, trending: false, status: 'published', views: 22000, likes: 18500 },
                { title: 'Nanook of the North (1922)', description: "The world's first feature-length documentary. Robert Flaherty's portrait of Inuit life — Nanook and his family hunting and surviving the brutal Arctic. A foundational work of cinema in the US Library of Congress.", type: 'documentary', category: 'Anthropology', language: 'Silent', year: 1922, duration: '79 min', rating: 7.8, videoUrl: 'https://archive.org/embed/nanook-of-the-north', thumbnailUrl: 'https://archive.org/services/img/nanook-of-the-north', featured: true, trending: false, status: 'published', views: 17000, likes: 13500 },
                { title: 'Man of Aran (1934)', description: "Robert Flaherty's masterpiece about the harsh life of Irish fisherfolk on the Aran Islands. Stunning cinematography of elemental struggle against the wild Atlantic. One of the greatest documentaries ever made.", type: 'documentary', category: 'Nature & People', language: 'English', year: 1934, duration: '76 min', rating: 7.9, videoUrl: 'https://archive.org/embed/ManOfAran', thumbnailUrl: 'https://archive.org/services/img/ManOfAran', featured: false, trending: true, status: 'published', views: 11500, likes: 9200 },
                { title: 'The City (1939)', description: 'A landmark American documentary about urban planning and the contrast between industrial cities and planned communities. Score by Aaron Copland. Listed in the US National Film Registry.', type: 'documentary', category: 'Urban History', language: 'English', year: 1939, duration: '44 min', rating: 7.8, videoUrl: 'https://archive.org/embed/theCity', thumbnailUrl: 'https://archive.org/services/img/theCity', featured: false, trending: false, status: 'published', views: 7200, likes: 5400 },
                { title: 'Housing Problems (1935)', description: 'A pioneering British social documentary where slum dwellers speak directly to camera — one of the first uses of the interview form in film. Arthur Elton and Edgar Anstey. A landmark of social realism.', type: 'documentary', category: 'Social History', language: 'English', year: 1935, duration: '15 min', rating: 7.3, videoUrl: 'https://archive.org/embed/HousingProblems', thumbnailUrl: 'https://archive.org/services/img/HousingProblems', featured: false, trending: false, status: 'published', views: 5100, likes: 3900 },
                { title: 'The Plow That Broke the Plains (1936)', description: "US government documentary about the Dust Bowl catastrophe and how decades of over-farming destroyed the Great Plains. Score by Virgil Thomson. One of America's first great government-produced films.", type: 'documentary', category: 'Environmental', language: 'English', year: 1936, duration: '28 min', rating: 7.5, videoUrl: 'https://archive.org/embed/ThePlowThatBrokethePlains', thumbnailUrl: 'https://archive.org/services/img/ThePlowThatBrokethePlains', featured: false, trending: false, status: 'published', views: 6400, likes: 4900 },
                { title: 'Listen to Britain (1942)', description: "Humphrey Jennings' impressionistic wartime documentary — Britain's soundscape during WWII. No narrator, just sounds and images of factories, music halls and streets. One of the finest British documentaries ever.", type: 'documentary', category: 'WWII History', language: 'English', year: 1942, duration: '19 min', rating: 8.0, videoUrl: 'https://archive.org/embed/ListentoBritain1942', thumbnailUrl: 'https://archive.org/services/img/ListentoBritain1942', featured: false, trending: false, status: 'published', views: 9000, likes: 7200 },
                { title: 'India: A Nation Under Siege (1944)', description: 'Rare WWII-era documentary about India's role in the Allied war effort — Indian Army, industrial mobilization and the social fabric of colonial India. An extraordinary time capsule from the US National Archives.', type: 'documentary', category: 'WWII History', language: 'English', year: 1944, duration: '18 min', rating: 7.6, videoUrl: 'https://archive.org/embed/india-a-nation-under-siege-1944', thumbnailUrl: 'https://archive.org/services/img/india-a-nation-under-siege-1944', featured: false, trending: false, status: 'published', views: 8500, likes: 6800 },
                { title: 'Triumph of the Will (1935)', description: "Leni Riefenstahl's groundbreaking and controversial documentary of the 1934 Nuremberg rally. Widely studied as the supreme example of propaganda cinema and a landmark of film technique.", type: 'documentary', category: 'Historical Study', language: 'German', year: 1935, duration: '114 min', rating: 7.4, videoUrl: 'https://archive.org/embed/TriumphOfTheWill', thumbnailUrl: 'https://archive.org/services/img/TriumphOfTheWill', featured: false, trending: false, status: 'published', views: 14000, likes: 8500 },

                // ===== LIVE (10) =====
                { title: 'Ravi Shankar — Monterey Pop Festival (1967)', description: "Pandit Ravi Shankar's historic sitar performance at Monterey that introduced Indian classical music to Western rock audiences. A transcendent raga that moved the crowd to meditation.", type: 'live', category: 'Classical Music', language: 'Instrumental', year: 1967, duration: '15 min', rating: 9.3, videoUrl: 'https://archive.org/embed/RaviShankarMonterey1967', thumbnailUrl: 'https://archive.org/services/img/RaviShankarMonterey1967', featured: true, trending: true, status: 'published', views: 48000, likes: 43000 },
                { title: 'M.S. Subbulakshmi — Carnegie Hall (1977)', description: 'M.S. Subbulakshmi's landmark Carnegie Hall performance — the first Carnatic vocalist to perform there. Legendary renditions of Bhaja Govindam and Venkateswara Suprabhatham.', type: 'live', category: 'Carnatic Vocal', language: 'Tamil/Sanskrit', year: 1977, duration: '96 min', rating: 9.4, videoUrl: 'https://archive.org/embed/MSSubbulakshmiCarnegieHall1977', thumbnailUrl: 'https://archive.org/services/img/MSSubbulakshmiCarnegieHall1977', featured: true, trending: true, status: 'published', views: 37000, likes: 33500 },
                { title: 'Kishore Kumar — Live Concert Ahmedabad (1985)', description: 'One of the last great recordings of Kishore Kumar — performing iconic Bollywood songs in a packed Ahmedabad stadium, two years before his passing. Includes Mohammed Rafi tributes.', type: 'live', category: 'Bollywood Music', language: 'Hindi', year: 1985, duration: '120 min', rating: 9.0, videoUrl: 'https://archive.org/embed/KishoreKumarLiveAhmedabad1985', thumbnailUrl: 'https://archive.org/services/img/KishoreKumarLiveAhmedabad1985', featured: true, trending: true, status: 'published', views: 54000, likes: 49000 },
                { title: 'Lata Mangeshkar — Royal Albert Hall (1974)', description: "The Nightingale of India performing live in London — Lag Ja Gale, Aye Mere Watan Ke Logon, and Tere Bina Zindagi Se. The first major Bollywood concert at the Royal Albert Hall.", type: 'live', category: 'Bollywood Music', language: 'Hindi', year: 1974, duration: '90 min', rating: 9.0, videoUrl: 'https://archive.org/embed/LataMangeshkarLiveLondon1974', thumbnailUrl: 'https://archive.org/services/img/LataMangeshkarLiveLondon1974', featured: false, trending: true, status: 'published', views: 41000, likes: 36500 },
                { title: 'Bismillah Khan — Shehnai at Varanasi Ghat', description: "Bharat Ratna Ustad Bismillah Khan performing shehnai at the sacred ghats of Varanasi — the city he never left. An irreplaceable document of North Indian classical tradition.", type: 'live', category: 'Classical Music', language: 'Instrumental', year: 1980, duration: '48 min', rating: 9.1, videoUrl: 'https://archive.org/embed/BismillahKhanShehnaiVaranasi', thumbnailUrl: 'https://archive.org/services/img/BismillahKhanShehnaiVaranasi', featured: true, trending: false, status: 'published', views: 28000, likes: 24000 },
                { title: 'Zakir Hussain — Tabla at WOMAD (1982)', description: "Ustad Zakir Hussain's breathtaking tabla solo and jugalbandi at the inaugural WOMAD festival. The performance that made Zakir Hussain an international superstar.", type: 'live', category: 'Classical Music', language: 'Instrumental', year: 1982, duration: '55 min', rating: 9.2, videoUrl: 'https://archive.org/embed/ZakirHussainTablaWOMAD1982', thumbnailUrl: 'https://archive.org/services/img/ZakirHussainTablaWOMAD1982', featured: false, trending: false, status: 'published', views: 23000, likes: 20000 },
                { title: 'Bhimsen Joshi — Sawai Gandharva Festival (1976)', description: "Pandit Bhimsen Joshi performing Raag Bhairav and Raag Miyan Ki Malhar at his own Sawai Gandharva Festival, Pune. The definitive live recording of Kirana Gharana Hindustani vocals.", type: 'live', category: 'Hindustani Vocal', language: 'Hindi/Sanskrit', year: 1976, duration: '80 min', rating: 9.3, videoUrl: 'https://archive.org/embed/BhimsenJoshiSawaiGandharva1976', thumbnailUrl: 'https://archive.org/services/img/BhimsenJoshiSawaiGandharva1976', featured: true, trending: false, status: 'published', views: 17500, likes: 15000 },
                { title: 'Girija Devi — Thumri at Benares (1983)', description: "Padma Vibhushan Girija Devi, Queen of Thumri, performing in Varanasi. A rare live recording of thumri, dadra and kajri — devotion, romance and playfulness in her fullest splendour.", type: 'live', category: 'Hindustani Semi-classical', language: 'Bhojpuri/Hindi', year: 1983, duration: '65 min', rating: 8.8, videoUrl: 'https://archive.org/embed/GirijaDeviThumriBenares1983', thumbnailUrl: 'https://archive.org/services/img/GirijaDeviThumriBenares1983', featured: false, trending: false, status: 'published', views: 12000, likes: 10200 },
                { title: 'Ali Akbar Khan — Sarod Recital (1955)', description: 'Ustad Ali Akbar Khan's celebrated early sarod recital — one of the first Indian classical LPs released in America. Disciple of Baba Allauddin Khan and brother-in-law of Ravi Shankar.', type: 'live', category: 'Hindustani Instrumental', language: 'Instrumental', year: 1955, duration: '52 min', rating: 9.0, videoUrl: 'https://archive.org/embed/AliAkbarKhanSarodRecital1955', thumbnailUrl: 'https://archive.org/services/img/AliAkbarKhanSarodRecital1955', featured: false, trending: false, status: 'published', views: 14200, likes: 12500 },
                { title: 'Nadaswaram Classical Concert (1970)', description: 'T.N. Rajarathnam Pillai performing the nadaswaram — the iconic South Indian temple wind instrument. One of the finest recordings of this rare instrument from the Films Division of India archives.', type: 'live', category: 'Carnatic Instrumental', language: 'Instrumental', year: 1970, duration: '42 min', rating: 8.5, videoUrl: 'https://archive.org/embed/NadaswaramClassical1970', thumbnailUrl: 'https://archive.org/services/img/NadaswaramClassical1970', featured: false, trending: false, status: 'published', views: 9500, likes: 8000 }
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
