const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const app = express();
const PORT = process.env.PORT || 3000;

// Database configuration
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'keerthi@#654',
    database: process.env.DB_NAME || 'project',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Session store configuration
const sessionStore = new MySQLStore({}, pool);

// Test database connection
async function testConnection() {
    let attempts = 0;
    const maxAttempts = 3;
    const retryDelay = 2000;

    while (attempts < maxAttempts) {
        try {
            const connection = await pool.getConnection();
            console.log('✅ Connected to MySQL database');
            
            // Verify the orphanage table exists
            const [tables] = await connection.query(
                "SHOW TABLES LIKE 'orphanage'"
            );
            
            if (tables.length === 0) {
                throw new Error("Orphanage table does not exist in database");
            }
            
            await connection.ping();
            connection.release();
            return;
        } catch (err) {
            attempts++;
            console.error(`❌ Database connection failed (attempt ${attempts}/${maxAttempts}):`, err.message);

            if (attempts === maxAttempts) {
                console.error('Could not establish database connection after multiple attempts');
                throw err;
            }

            await new Promise(resolve => setTimeout(resolve, retryDelay));
        }
    }
}

// Middleware setup
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:8080',
    credentials: true
}));

// Session middleware
app.use(session({
    key: 'orphanage_system_session',
    secret: 'your_strong_secret_key_here',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production'
    }
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static files from frontend directory
const FRONTEND_PATH = path.join(__dirname, '../frontend');
app.use(express.static(FRONTEND_PATH));

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('❌ Server error:', err.stack || err.message || err);
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? {
            message: err.message,
            stack: err.stack
        } : undefined
    });
});

// Routes
app.get('/home', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(FRONTEND_PATH, 'homepage.html'));
});
app.get('/', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(FRONTEND_PATH, 'login.html'));
});

app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(FRONTEND_PATH, 'login.html'));
});

app.get('/signup', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(FRONTEND_PATH, 'signup.html'));
});

app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(FRONTEND_PATH, 'O_dashboard.html'));
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ 
            status: 'healthy',
            database: 'connected',
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        res.status(500).json({ 
            status: 'unhealthy',
            database: 'disconnected',
            error: err.message
        });
    }
});

// Signup endpoint with proper orphanage_type handling
app.post('/api/signup', async (req, res, next) => {
    let connection;
    try {
        connection = await pool.getConnection();

        // Validate required fields
        const requiredFields = {
            orphanage_name: 'Orphanage name',
            registration_number: 'Registration number',
            address: 'Address',
            city: 'City',
            state_province: 'State/Province',
            country: 'Country',
            phone_number: 'Phone number',
            email: 'Email address',
            admin_name: 'Admin name',
            admin_position: 'Admin position',
            admin_phone: 'Admin phone',
            admin_email: 'Admin email',
            username: 'Username',
            password: 'Password'
        };

        const missingFields = Object.entries(requiredFields)
            .filter(([field]) => !req.body[field])
            .map(([_, name]) => name);

        if (missingFields.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields',
                missingFields,
                details: `Please provide: ${missingFields.join(', ')}`
            });
        }

        // Process input data
        const {
            orphanage_name, registration_number, orphanage_type = 'other',
            year_established, address, city, state_province, country,
            postal_code = '', phone_number, email, website,
            capacity = 0, current_staff_count = 0, mission_statement,
            registration_documents_path, admin_name, admin_position,
            admin_phone, admin_email, id_proof_path, username, password
        } = req.body;

        // Validate email format
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid email format'
            });
        }

        // Validate password strength
        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long'
            });
        }

        // Validate orphanage_type
        const validOrphanageTypes = ['government', 'private', 'religious', 'community', 'other'];
        if (!validOrphanageTypes.includes(orphanage_type)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid orphanage type',
                validTypes: validOrphanageTypes
            });
        }

        // Check for existing user
        await connection.beginTransaction();
        try {
            const [existing] = await connection.query(
                'SELECT id FROM orphanage WHERE username = ? OR email = ? LIMIT 1 FOR UPDATE',
                [username, email]
            );

            if (existing.length > 0) {
                await connection.rollback();
                return res.status(409).json({
                    success: false,
                    message: 'Username or email already exists.',
                    conflict: existing[0].username === username ? 'username' : 'email'
                });
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 12);

            // Prepare data for insertion
            const orphanageData = {
                orphanage_name,
                registration_number,
                orphanage_type,
                year_established: year_established || null,
                address,
                city,
                state_province,
                country,
                postal_code,
                phone_number,
                email,
                website: website || null,
                capacity,
                current_staff_count,
                mission_statement: mission_statement || null,
                registration_documents_path: registration_documents_path || null,
                admin_name,
                admin_position,
                admin_phone,
                admin_email,
                id_proof_path: id_proof_path || null,
                username,
                password_hash: hashedPassword,
                created_at: new Date(),
                updated_at: new Date()
            };

            // Insert into database
            const [result] = await connection.query('INSERT INTO orphanage SET ?', orphanageData);
            await connection.commit();

            return res.status(201).json({
                success: true,
                message: 'Signup successful',
                orphanageId: result.insertId,
                redirect: '/login'
            });
        } catch (txErr) {
            await connection.rollback();
            
            // Handle specific MySQL errors
            if (txErr.code === 'WARN_DATA_TRUNCATED') {
                return res.status(400).json({
                    success: false,
                    message: 'Signup Successful',
                    details: txErr.sqlMessage,
                    field: txErr.sqlMessage.match(/column '(.+?)'/)[1]
                });
            }
            
            throw txErr;
        }
    } catch (err) {
        console.error('Signup error:', {
            message: err.message,
            stack: err.stack,
            body: req.body
        });
        next(err);
    } finally {
        if (connection) connection.release();
    }
});

// Login endpoint
app.post('/api/login', async (req, res, next) => {
    let connection;
    try {
        connection = await pool.getConnection();

        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required.'
            });
        }

        const [results] = await connection.query(
            `SELECT id, username, email, password_hash 
             FROM orphanage 
             WHERE BINARY username = ? 
             LIMIT 1`,
            [username]
        );

        if (results.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Set session
        req.session.userId = user.id;

        res.status(200).json({
            success: true,
            message: 'Login successful',
            redirect: '/dashboard'
        });

    } catch (err) {
        console.error('Login error:', err);
        next(err);
    } finally {
        if (connection) connection.release();
    }
});

// Dashboard data endpoint
app.get('/api/dashboard', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ 
            success: false, 
            message: 'Not authenticated' 
        });
    }

    try {
        const [user] = await pool.query(
            'SELECT id, orphanage_name, email, address, phone_number FROM orphanage WHERE id = ?',
            [req.session.userId]
        );

        if (user.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        res.json({
            success: true,
            user: user[0]
        });
    } catch (err) {
        console.error('Dashboard error:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Logout failed' 
            });
        }
        res.clearCookie('orphanage_system_session');
        res.json({ 
            success: true, 
            message: 'Logged out successfully',
            redirect: '/login'
        });
    });
});

// Start server
async function startServer() {
    try {
        await testConnection();
        
        app.listen(PORT, () => {
            console.log(`🚀 Server running at http://localhost:${PORT}`);
            console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`Serving files from: ${FRONTEND_PATH}`);
        });

        // Graceful shutdown
        process.on('SIGTERM', () => {
            console.log('SIGTERM received. Shutting down gracefully...');
            pool.end();
            process.exit(0);
        });

        process.on('SIGINT', () => {
            console.log('SIGINT received. Shutting down gracefully...');
            pool.end();
            process.exit(0);
        });
    } catch (err) {
        console.error('Failed to start server:', err);
        process.exit(1);
    }
}

startServer();