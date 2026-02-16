const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;
const cors = require('cors');

// Middleware
// CORS Configuration
// CRITICAL: CORS must be configured BEFORE routes
const corsOptions = {
    origin: 'https://classicflims.up.railway.app',  // NO trailing slash
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    optionsSuccessStatus: 200
};

// Apply CORS to ALL routes - MUST be before any route definitions
app.use(cors(corsOptions));

// Explicitly handle preflight requests
app.options('*', cors(corsOptions));

app.use(express.static(__dirname));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
