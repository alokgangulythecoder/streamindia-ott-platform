// frontend-config.js - Frontend Configuration for Backend Integration

// Add this to your ott-streaming-app.html in the <script type="text/babel"> section

const API_CONFIG = {
    BASE_URL: 'http://localhost:3000/api',
    ENDPOINTS: {
        // Content
        CONTENT: '/content',
        CONTENT_BY_ID: (id) => `/content/${id}`,
        CONTENT_VIEW: (id) => `/content/${id}/view`,
        
        // Navigation
        NAVIGATION: '/navigation',
        
        // Advertisements
        ADS: '/advertisements',
        AD_IMPRESSION: (id) => `/advertisements/${id}/impression`,
        AD_CLICK: (id) => `/advertisements/${id}/click`,
        
        // Settings
        SETTINGS: '/settings'
    }
};

// API Helper Functions
const api = {
    // Fetch content with filters
    getContent: async (filters = {}) => {
        const params = new URLSearchParams(filters);
        const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.CONTENT}?${params}`);
        return await response.json();
    },

    // Get single content
    getContentById: async (id) => {
        const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.CONTENT_BY_ID(id)}`);
        return await response.json();
    },

    // Increment view count
    trackView: async (id) => {
        await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.CONTENT_VIEW(id)}`, {
            method: 'POST'
        });
    },

    // Get navigation menu
    getNavigation: async () => {
        const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.NAVIGATION}`);
        return await response.json();
    },

    // Get advertisements
    getAds: async (position, type) => {
        const params = new URLSearchParams({ position, type });
        const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.ADS}?${params}`);
        return await response.json();
    },

    // Track ad impression
    trackAdImpression: async (id) => {
        await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.AD_IMPRESSION(id)}`, {
            method: 'POST'
        });
    },

    // Track ad click
    trackAdClick: async (id) => {
        await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.AD_CLICK(id)}`, {
            method: 'POST'
        });
    },

    // Get settings
    getSettings: async () => {
        const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SETTINGS}`);
        return await response.json();
    }
};

// ==========================================
// UPDATED APP COMPONENT WITH BACKEND INTEGRATION
// ==========================================

// Replace the existing mockContent and App function with this:

function App() {
    const [activeCategory, setActiveCategory] = useState("All");
    const [scrolled, setScrolled] = useState(false);
    const [activeNav, setActiveNav] = useState("Home");
    const [playerOpen, setPlayerOpen] = useState(false);
    const [selectedContent, setSelectedContent] = useState(null);
    const [youtubeVideos, setYoutubeVideos] = useState([]);
    const [backendContent, setBackendContent] = useState({
        trending: [],
        movies: [],
        series: [],
        featured: []
    });
    const [navigation, setNavigation] = useState([]);
    const [headerAd, setHeaderAd] = useState(null);
    const [sidebarAds, setSidebarAds] = useState([]);
    const [settings, setSettings] = useState({});
    const [loading, setLoading] = useState(true);

    // Fetch all data on component mount
    useEffect(() => {
        loadAllData();
    }, []);

    const loadAllData = async () => {
        setLoading(true);
        
        try {
            // Load content from backend
            const [trendingData, moviesData, seriesData, featuredData] = await Promise.all([
                api.getContent({ trending: true, limit: 12 }),
                api.getContent({ type: 'movie', limit: 12 }),
                api.getContent({ type: 'series', limit: 12 }),
                api.getContent({ featured: true, limit: 12 })
            ]);

            setBackendContent({
                trending: trendingData.content || [],
                movies: moviesData.content || [],
                series: seriesData.content || [],
                featured: featuredData.content || []
            });

            // Load navigation
            const navData = await api.getNavigation();
            setNavigation(navData || []);

            // Load advertisements
            const headerAdData = await api.getAds('header', 'banner');
            const sidebarAdData = await api.getAds('sidebar', 'banner');
            
            if (headerAdData.length > 0) {
                setHeaderAd(headerAdData[0]);
                api.trackAdImpression(headerAdData[0]._id);
            }
            setSidebarAds(sidebarAdData || []);

            // Load settings
            const settingsData = await api.getSettings();
            setSettings(settingsData);

            // Apply dynamic theme if available
            if (settingsData.primary_color) {
                document.documentElement.style.setProperty('--accent-primary', settingsData.primary_color);
            }
            if (settingsData.secondary_color) {
                document.documentElement.style.setProperty('--accent-secondary', settingsData.secondary_color);
            }

            // Update site title
            if (settingsData.site_name) {
                document.title = settingsData.site_name + ' - Premium OTT Platform';
            }

            // Load YouTube videos (keeping existing functionality)
            const videos = await fetchYouTubeVideos(12);
            setYoutubeVideos(videos);

        } catch (error) {
            console.error('Error loading data:', error);
            // Fallback to mock data if backend is unavailable
            console.log('Using fallback mock data');
        }
        
        setLoading(false);
    };

    useEffect(() => {
        const handleScroll = () => {
            setScrolled(window.scrollY > 50);
        };
        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    const playContent = (content) => {
        setSelectedContent(content);
        setPlayerOpen(true);
        
        // Track view
        if (content._id) {
            api.trackView(content._id);
        }
    };

    const handleAdClick = (ad) => {
        if (ad._id) {
            api.trackAdClick(ad._id);
        }
        if (ad.clickUrl) {
            window.open(ad.clickUrl, '_blank');
        }
    };

    // Advertisement Component
    const AdBanner = ({ ad, position }) => {
        if (!ad) return null;

        return (
            <div 
                className={`ad-banner ad-${position}`}
                onClick={() => handleAdClick(ad)}
                style={{ cursor: ad.clickUrl ? 'pointer' : 'default' }}
            >
                {ad.imageUrl && (
                    <img src={ad.imageUrl} alt={ad.title} style={{ width: '100%', borderRadius: '8px' }} />
                )}
                {ad.type === 'video' && ad.videoUrl && (
                    <video 
                        src={ad.videoUrl} 
                        autoPlay 
                        muted 
                        loop 
                        style={{ width: '100%', borderRadius: '8px' }}
                    />
                )}
            </div>
        );
    };

    const ContentCard = ({ content }) => (
        <div className="content-card" tabIndex="0">
            <img src={content.thumbnail || content.image} alt={content.title} className="card-image" />
            {content.badge && <div className="card-badge">{content.badge}</div>}
            <div className="card-overlay">
                <div className="card-title">{content.title}</div>
                <div className="card-meta">
                    <span>{content.type}</span>
                    <span>•</span>
                    <span>{content.year}</span>
                    {content.language && (
                        <>
                            <span>•</span>
                            <span>{content.language}</span>
                        </>
                    )}
                </div>
                {content.rating && (
                    <div className="card-rating">
                        <span>⭐</span>
                        <span>{content.rating}</span>
                    </div>
                )}
                {content.views > 0 && (
                    <div className="card-meta">
                        <span>👁️ {content.views.toLocaleString()} views</span>
                    </div>
                )}
                <div className="card-actions">
                    <button className="card-btn card-btn-play" onClick={() => playContent(content)}>
                        ▶ Play
                    </button>
                    <button className="card-btn card-btn-info">ℹ Info</button>
                </div>
            </div>
        </div>
    );

    // Rest of the component remains the same...
    // Use backendContent instead of mockContent for rendering
}

// ==========================================
// CSS ADDITIONS FOR ADVERTISEMENTS
// ==========================================

/* Add these styles to your existing CSS */

const adStyles = `
    .ad-banner {
        margin: 2rem 0;
        transition: all 0.3s ease;
    }

    .ad-banner:hover {
        transform: scale(1.02);
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
    }

    .ad-header {
        position: sticky;
        top: 80px;
        z-index: 100;
        animation: slideDown 0.5s ease;
    }

    .ad-sidebar {
        position: sticky;
        top: 100px;
    }

    @keyframes slideDown {
        from {
            opacity: 0;
            transform: translateY(-20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    .ad-close-btn {
        position: absolute;
        top: 10px;
        right: 10px;
        background: rgba(0, 0, 0, 0.7);
        color: white;
        border: none;
        width: 30px;
        height: 30px;
        border-radius: 50%;
        cursor: pointer;
        font-size: 1.2rem;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .ad-close-btn:hover {
        background: var(--accent-primary);
    }
`;

// ==========================================
// EXAMPLE USAGE IN JSX
// ==========================================

/*
In your return statement, add advertisements like this:

return (
    <div className="app-container">
        <div className="bg-ambience"></div>

        {/* Header Advertisement *\/}
        {headerAd && <AdBanner ad={headerAd} position="header" />}

        {/* Navigation - use dynamic navigation from backend *\/}
        <nav className={`navbar ${scrolled ? 'scrolled' : ''}`}>
            <div className="logo">{settings.site_name || 'StreamIndia'}</div>
            <ul className="nav-menu">
                {navigation.map(item => (
                    <li 
                        key={item._id}
                        className={`nav-item ${activeNav === item.label ? 'active' : ''}`}
                        onClick={() => setActiveNav(item.label)}
                        tabIndex="0"
                    >
                        {item.icon && <span>{item.icon}</span>}
                        {item.label}
                    </li>
                ))}
            </ul>
            {/* ... rest of nav *\/}
        </nav>

        {/* Content sections using backendContent *\/}
        <section className="content-section">
            <div className="section-header">
                <h2 className="section-title">🔥 Trending Now</h2>
                <span className="view-all" tabIndex="0">View All →</span>
            </div>
            <Carousel items={backendContent.trending} isLoading={loading} />
        </section>

        {/* Sidebar Advertisement *\/}
        {sidebarAds.map(ad => (
            <AdBanner key={ad._id} ad={ad} position="sidebar" />
        ))}

        {/* ... rest of your content *\/}
    </div>
);
*/
