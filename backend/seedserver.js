// ============================================================
// SEED SERVER — Standalone Data Ingestion Tool
// ============================================================
// Purpose: Add content to MongoDB via Postman/API calls
// Run: node seed-server.js
// Then use Postman to POST JSON data
// ============================================================

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
const PORT = process.env.SEED_PORT || 4000;

// ========================================
// MIDDLEWARE
// ========================================
app.use(cors());
app.use(express.json({ limit: '50mb' })); // Large JSON support
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// ========================================
// MONGODB CONNECTION
// ========================================
const MONGODB_URI = process.env.MONGO_URI || process.env.MONGODB_URI;

if (!MONGODB_URI) {
    console.error('❌ MONGO_URI environment variable not set');
    process.exit(1);
}

console.log('🔄 Connecting to MongoDB...');
mongoose.connect(MONGODB_URI)
    .then(() => {
        console.log('✅ MongoDB Connected');
        console.log('📊 Database:', mongoose.connection.name);
    })
    .catch((error) => {
        console.error('❌ MongoDB Error:', error.message);
        process.exit(1);
    });

// ========================================
// SCHEMAS (Same as main server)
// ========================================

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

const Content = mongoose.model('Content', contentSchema);
const Navigation = mongoose.model('Navigation', navigationSchema);
const Advertisement = mongoose.model('Advertisement', advertisementSchema);
const Settings = mongoose.model('Settings', settingsSchema);

// ========================================
// BASIC ROUTES
// ========================================

app.get('/', (req, res) => {
    res.json({
        server: 'ClassicFlims Seed Server',
        version: '1.0.0',
        status: 'running',
        endpoints: {
            bulk_insert: 'POST /api/bulk-insert',
            add_content: 'POST /api/content',
            add_navigation: 'POST /api/navigation',
            add_advertisement: 'POST /api/advertisement',
            add_settings: 'POST /api/settings',
            view_all: 'GET /api/view-all',
            clear_all: 'DELETE /api/clear-all',
            stats: 'GET /api/stats'
        }
    });
});

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        port: PORT
    });
});

// ========================================
// BULK INSERT — Add Multiple Items at Once
// ========================================
app.post('/api/bulk-insert', async (req, res) => {
    try {
        const { content, navigation, advertisements, settings } = req.body;
        const results = {};

        // Insert Content
        if (content && Array.isArray(content) && content.length > 0) {
            const inserted = await Content.insertMany(content);
            results.content = { count: inserted.length, items: inserted };
        }

        // Insert Navigation
        if (navigation && Array.isArray(navigation) && navigation.length > 0) {
            const inserted = await Navigation.insertMany(navigation);
            results.navigation = { count: inserted.length, items: inserted };
        }

        // Insert Advertisements
        if (advertisements && Array.isArray(advertisements) && advertisements.length > 0) {
            const inserted = await Advertisement.insertMany(advertisements);
            results.advertisements = { count: inserted.length, items: inserted };
        }

        // Insert Settings
        if (settings && Array.isArray(settings) && settings.length > 0) {
            const inserted = await Settings.insertMany(settings);
            results.settings = { count: inserted.length, items: inserted };
        }

        console.log('✅ Bulk insert successful:', {
            content: results.content?.count || 0,
            navigation: results.navigation?.count || 0,
            advertisements: results.advertisements?.count || 0,
            settings: results.settings?.count || 0
        });

        res.status(201).json({
            success: true,
            message: 'Bulk insert successful',
            results
        });

    } catch (error) {
        console.error('❌ Bulk insert error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ========================================
// INDIVIDUAL INSERT ROUTES
// ========================================

// Add Content (single or multiple)
app.post('/api/content', async (req, res) => {
    try {
        const data = Array.isArray(req.body) ? req.body : [req.body];
        const inserted = await Content.insertMany(data);
        console.log(`✅ Added ${inserted.length} content item(s)`);
        res.status(201).json({
            success: true,
            count: inserted.length,
            items: inserted
        });
    } catch (error) {
        console.error('❌ Content insert error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Add Navigation (single or multiple)
app.post('/api/navigation', async (req, res) => {
    try {
        const data = Array.isArray(req.body) ? req.body : [req.body];
        const inserted = await Navigation.insertMany(data);
        console.log(`✅ Added ${inserted.length} navigation item(s)`);
        res.status(201).json({
            success: true,
            count: inserted.length,
            items: inserted
        });
    } catch (error) {
        console.error('❌ Navigation insert error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Add Advertisement (single or multiple)
app.post('/api/advertisement', async (req, res) => {
    try {
        const data = Array.isArray(req.body) ? req.body : [req.body];
        const inserted = await Advertisement.insertMany(data);
        console.log(`✅ Added ${inserted.length} advertisement(s)`);
        res.status(201).json({
            success: true,
            count: inserted.length,
            items: inserted
        });
    } catch (error) {
        console.error('❌ Advertisement insert error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Add Settings (single or multiple)
app.post('/api/settings', async (req, res) => {
    try {
        const data = Array.isArray(req.body) ? req.body : [req.body];
        const inserted = await Settings.insertMany(data);
        console.log(`✅ Added ${inserted.length} setting(s)`);
        res.status(201).json({
            success: true,
            count: inserted.length,
            items: inserted
        });
    } catch (error) {
        console.error('❌ Settings insert error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// VIEW & STATS ROUTES
// ========================================

app.get('/api/view-all', async (req, res) => {
    try {
        const [content, navigation, advertisements, settings] = await Promise.all([
            Content.find().sort({ createdAt: -1 }),
            Navigation.find().sort({ order: 1 }),
            Advertisement.find().sort({ createdAt: -1 }),
            Settings.find()
        ]);

        res.json({
            success: true,
            data: {
                content: { count: content.length, items: content },
                navigation: { count: navigation.length, items: navigation },
                advertisements: { count: advertisements.length, items: advertisements },
                settings: { count: settings.length, items: settings }
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const stats = {
            content: {
                total: await Content.countDocuments(),
                movies: await Content.countDocuments({ type: 'movie' }),
                series: await Content.countDocuments({ type: 'series' }),
                documentaries: await Content.countDocuments({ type: 'documentary' }),
                live: await Content.countDocuments({ type: 'live' }),
                featured: await Content.countDocuments({ featured: true }),
                trending: await Content.countDocuments({ trending: true }),
                published: await Content.countDocuments({ status: 'published' })
            },
            navigation: await Navigation.countDocuments(),
            advertisements: await Advertisement.countDocuments(),
            settings: await Settings.countDocuments()
        };

        console.log('📊 Stats requested:', stats);
        res.json({ success: true, stats });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// CLEAR DATABASE (USE WITH CAUTION)
// ========================================

app.delete('/api/clear-all', async (req, res) => {
    try {
        const confirmation = req.query.confirm;
        
        if (confirmation !== 'YES_DELETE_ALL') {
            return res.status(400).json({
                success: false,
                error: 'Missing confirmation',
                message: 'Add query param: ?confirm=YES_DELETE_ALL'
            });
        }

        const results = await Promise.all([
            Content.deleteMany({}),
            Navigation.deleteMany({}),
            Advertisement.deleteMany({}),
            Settings.deleteMany({})
        ]);

        console.log('🗑️  Database cleared:', {
            content: results[0].deletedCount,
            navigation: results[1].deletedCount,
            advertisements: results[2].deletedCount,
            settings: results[3].deletedCount
        });

        res.json({
            success: true,
            message: 'All data cleared',
            deleted: {
                content: results[0].deletedCount,
                navigation: results[1].deletedCount,
                advertisements: results[2].deletedCount,
                settings: results[3].deletedCount
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// ERROR HANDLERS
// ========================================

app.use((req, res) => {
    res.status(404).json({
        error: 'Route not found',
        path: req.path,
        availableEndpoints: [
            'POST /api/bulk-insert',
            'POST /api/content',
            'POST /api/navigation',
            'POST /api/advertisement',
            'POST /api/settings',
            'GET /api/view-all',
            'GET /api/stats',
            'DELETE /api/clear-all?confirm=YES_DELETE_ALL'
        ]
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
    console.log('='.repeat(60));
    console.log('🌱 SEED SERVER STARTED');
    console.log(`🚀 Listening on http://0.0.0.0:${PORT}`);
    console.log('='.repeat(60));
    console.log('📍 Endpoints:');
    console.log(`   POST   http://localhost:${PORT}/api/bulk-insert`);
    console.log(`   POST   http://localhost:${PORT}/api/content`);
    console.log(`   POST   http://localhost:${PORT}/api/navigation`);
    console.log(`   POST   http://localhost:${PORT}/api/advertisement`);
    console.log(`   POST   http://localhost:${PORT}/api/settings`);
    console.log(`   GET    http://localhost:${PORT}/api/view-all`);
    console.log(`   GET    http://localhost:${PORT}/api/stats`);
    console.log(`   DELETE http://localhost:${PORT}/api/clear-all?confirm=YES_DELETE_ALL`);
    console.log('='.repeat(60));
});

app.on('error', (error) => {
    console.error('❌ Server error:', error);
    if (error.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use`);
        process.exit(1);
    }
});

process.on('SIGTERM', () => {
    mongoose.connection.close(false, () => {
        console.log('MongoDB connection closed');
        process.exit(0);
    });
});
