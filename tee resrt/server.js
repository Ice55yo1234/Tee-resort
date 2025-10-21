// --- Backend Application (Node.js with Express & SQLite) ---

// 1. Import Dependencies
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcrypt');
const path = require('path');

// 2. Initial Setup
const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 10;
const ADMIN_TOKEN_SECRET = 'your-very-secret-key-for-admin';

// 3. Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));


// 4. Database Connection
const db = new sqlite3.Database('./tee_resort.db', (err) => {
    if (err) console.error("Error opening database", err.message);
    else {
        console.log("Connected to the SQLite database.");
        db.serialize(() => {
            db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL)`);
            db.run(`
                CREATE TABLE IF NOT EXISTS bookings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_email TEXT NOT NULL,
                    room_id INTEGER NOT NULL,
                    check_in_date TEXT NOT NULL,
                    check_out_date TEXT NOT NULL,
                    total_price REAL NOT NULL,
                    status TEXT DEFAULT 'Pending', 
                    booking_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
            db.all("PRAGMA table_info(bookings)", (err, columns) => {
                if (err) {
                    console.error("Error checking bookings table schema:", err.message);
                    return;
                }
                if (columns && !columns.some(col => col.name === 'status')) {
                    console.log("Adding 'status' column to bookings table...");
                    db.run("ALTER TABLE bookings ADD COLUMN status TEXT DEFAULT 'Pending'", (alterErr) => {
                        if (alterErr) {
                            console.error("Error adding 'status' column:", alterErr.message);
                        }
                    });
                }
            });
        });
    }
});

// --- Middleware for Admin Auth ---
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null || token !== ADMIN_TOKEN_SECRET) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    next();
};


// 5. API Routes

// --- Customer Routes ---
app.post('/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Please provide both email and password." });
    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) return res.status(500).json({ message: "Error hashing password." });
        const sql = `INSERT INTO users (email, password) VALUES (?, ?)`;
        db.run(sql, [email, hash], function(err) {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT') return res.status(409).json({ message: "This email is already registered." });
                return res.status(500).json({ message: "Database error during registration." });
            }
            res.status(201).json({ message: "User registered successfully!", userId: this.lastID });
        });
    });
});
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Please provide both email and password." });
    const sql = `SELECT * FROM users WHERE email = ?`;
    db.get(sql, [email], (err, user) => {
        if (err) return res.status(500).json({ message: "Database error during login." });
        if (!user) return res.status(401).json({ message: "Invalid email or password." });
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) return res.status(500).json({ message: "Error comparing password." });
            if (result) res.status(200).json({ message: "Login successful!", email: user.email });
            else res.status(401).json({ message: "Invalid email or password." });
        });
    });
});
app.post('/bookings', (req, res) => {
    const { email, roomId, checkIn, checkOut, totalPrice } = req.body;
    if (!email || !roomId || !checkIn || !checkOut || !totalPrice) return res.status(400).json({ message: "Incomplete booking information." });
    const sql = `INSERT INTO bookings (user_email, room_id, check_in_date, check_out_date, total_price) VALUES (?, ?, ?, ?, ?)`;
    db.run(sql, [email, roomId, checkIn, checkOut, totalPrice], function(err) {
        if (err) return res.status(500).json({ message: "Failed to create booking." });
        res.status(201).json({ message: "Booking created successfully!", bookingId: this.lastID });
    });
});


// --- Admin API Routes ---
app.post('/api/admin/login', (req, res) => {
    const { email, password } = req.body;
    if (email === 'admin@resort.com' && password === 'password123') {
        res.json({ message: "Login successful", token: ADMIN_TOKEN_SECRET });
    } else {
        res.status(401).json({ message: "Invalid admin credentials" });
    }
});

app.get('/api/bookings', authenticateAdmin, (req, res) => {
    const sql = `SELECT * FROM bookings`;
    db.all(sql, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: "Error fetching bookings." });
        }
        res.json(rows);
    });
});

app.put('/api/bookings/:id/status', authenticateAdmin, (req, res) => {
    const { status } = req.body;
    const { id } = req.params;

    if (!status) {
        return res.status(400).json({ message: "Status is required." });
    }

    const sql = `UPDATE bookings SET status = ? WHERE id = ?`;
    db.run(sql, [status, id], function(err) {
        if (err) {
            return res.status(500).json({ message: "Failed to update booking status." });
        }
        if (this.changes === 0) {
            return res.status(404).json({ message: "Booking not found." });
        }
        res.json({ message: `Booking #${id} status updated to ${status}` });
    });
});


// 6. Start the Server
app.listen(PORT, () => {
    console.log(`Tee Resort server is running on port ${PORT}`);
});

