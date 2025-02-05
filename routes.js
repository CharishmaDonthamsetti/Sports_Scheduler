const express = require('express');
const bcrypt = require('bcryptjs');
const pool = require('./database');
const router = express.Router();

const session = require('express-session');
const flash = require('connect-flash');
const app = express();

app.use(session({
    secret: 'your-secret-key', 
    resave: false,
    saveUninitialized: true
}));

app.use(flash());

app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    next();
});


const isAuthenticated = (req, res, next) => {
    if (req.session.user) return next();
    res.redirect('/login');
};

const isAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.role === 'admin') return next();
    res.redirect('/');
};

router.get('/', (req, res) => res.render('home'));


router.get('/register', (req, res) => res.render('register'));

router.post('/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userExists.rowCount) {
            return res.render('register', { error: 'Email already in use!' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)', 
            [name, email, hashedPassword, role]);

        res.redirect('/login');
    } catch (error) {
        console.error("Error registering user:", error);
        res.status(500).send("Server Error");
    }
});


router.get('/login', (req, res) => res.render('login'));

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

        if (user.rowCount && await bcrypt.compare(password, user.rows[0].password)) {
            req.session.user = user.rows[0];
            return res.redirect(user.rows[0].role === 'admin' ? '/admin-dashboard' : '/player-dashboard');
        }
        res.redirect('/login');
    } catch (error) {
        console.error("Error logging in:", error);
        res.status(500).send("Server Error");
    }
});


router.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});


router.get('/admin-dashboard', isAdmin, async (req, res) => {
    try {
        const sports = await pool.query('SELECT * FROM sports');

        const sessions = await pool.query(`
            SELECT se.id, se.venue, se.date_time, s.name AS sport_name 
            FROM sessions se
            JOIN sports s ON se.sport_id = s.id
            WHERE se.status = $1
        `, ['upcoming']);

        const joinedSessions = await pool.query(`
            SELECT se.id, se.venue, se.date_time, s.name AS sport_name
            FROM session_participants sp
            JOIN sessions se ON sp.session_id = se.id
            JOIN sports s ON se.sport_id = s.id
            WHERE sp.user_id = $1
        `, [req.session.user.id]); 

        res.render('admin-dashboard', { 
            sports: sports.rows, 
            sessions: sessions.rows,
            joinedSessions: joinedSessions.rows
        });

    } catch (error) {
        console.error("Error fetching dashboard data:", error);
        res.status(500).send("Server Error");
    }
});

router.post('/admin/add-sport', isAdmin, async (req, res) => {
    try {
        await pool.query('INSERT INTO sports (name) VALUES ($1)', [req.body.sport_name]);
        res.redirect('/admin-dashboard');
    } catch (error) {
        console.error("Error adding sport:", error);
        res.redirect('/admin-dashboard');
    }
});

router.get('/player-dashboard', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.user.id; // Use req.session.user instead of req.user

        const sportsQuery = 'SELECT * FROM sports';
        const sportsResult = await pool.query(sportsQuery);

        const sessionsQuery = `
            SELECT s.name AS sport_name, se.* 
            FROM sessions se 
            JOIN sports s ON se.sport_id = s.id 
            WHERE se.status = $1
        `;
        const sessionsResult = await pool.query(sessionsQuery, ['upcoming']);

        const joinedSessionsQuery = `
            SELECT s.name AS sport_name, se.* 
            FROM session_participants sp
            JOIN sessions se ON sp.session_id = se.id
            JOIN sports s ON se.sport_id = s.id
            WHERE sp.user_id = $1
        `;
        const joinedSessionsResult = await pool.query(joinedSessionsQuery, [userId]);

        res.render('player-dashboard', { 
            sessions: sessionsResult.rows, 
            sports: sportsResult.rows,
            joinedSessions: joinedSessionsResult.rows 
        });

    } catch (error) {
        console.error("❌ Error fetching player dashboard:", error.message, error.stack);
        res.status(500).send("Internal Server Error");
    }
});


router.post('/sessions', isAuthenticated, async (req, res) => {
    try {
        const { sport_id, venue, date_time } = req.body;
        const user = req.session.user; // Fetch user object
        const userId = user.id; 

        await pool.query(
            'INSERT INTO sessions (sport_id, created_by, date_time, venue, status) VALUES ($1, $2, $3, $4, $5)', 
            [sport_id, userId, date_time, venue, 'upcoming']
        );


        if (user.role === 'admin') {
            res.redirect('/admin-dashboard'); // Redirect admin to admin dashboard
        } else {
            res.redirect('/player-dashboard'); // Redirect players to player dashboard
        }

    } catch (error) {
        console.error("Error creating session:", error.message, error.stack);
        res.status(500).send("Server Error");
    }
});


router.post('/sessions/join/:id', isAuthenticated, async (req, res) => {
    try {
        const sessionId = req.params.id;
        const userId = req.session.user.id; 
        const userRole = req.session.user.role; 

        const sessionQuery = await pool.query(
            'SELECT * FROM sessions WHERE id = $1',
            [sessionId]
        );

        const session = sessionQuery.rows[0];
        const sessionDate = new Date(session.date_time);
        const currentDate = new Date();


        if (sessionDate < currentDate) {
            // If the session is in the past, do not allow joining
            if (userRole === 'admin') {
                return res.redirect('/admin-dashboard');
            } else {
                return res.redirect('/player-dashboard');
            }
            alert("session is over"); 
        }

        const checkIfAlreadyJoined = await pool.query(
            'SELECT * FROM session_participants WHERE session_id = $1 AND user_id = $2',
            [sessionId, userId]
        );

        if (checkIfAlreadyJoined.rows.length > 0) {
            if (userRole === 'admin') {
                return res.redirect('/admin-dashboard'); 
            } else {
                return res.redirect('/player-dashboard'); 
            }
        }

        await pool.query(
            'INSERT INTO session_participants (session_id, user_id) VALUES ($1, $2)', 
            [sessionId, userId]
        );

        if (userRole === 'admin') {
            return res.redirect('/admin-dashboard');
        } else {
            return res.redirect('/player-dashboard');
        }
    } catch (error) {
        console.error("Error joining session:", error.message, error.stack);
        res.status(500).send("Server Error");
    }
});


router.get('/reports', isAdmin, async (req, res) => {
    try {
        
        const report = await pool.query(
            `SELECT 
                s.name AS sport_name, 
                se.id AS session_id, 
                se.venue, 
                se.date_time, 
                u.name AS player_name
            FROM sessions se
            JOIN sports s ON se.sport_id = s.id
            LEFT JOIN session_participants sp ON se.id = sp.session_id
            LEFT JOIN users u ON sp.user_id = u.id
            ORDER BY s.name, se.date_time`
        );

        
        res.render('reports', { report: report.rows });
    } catch (error) {
        console.error("Error fetching reports:", error.message);
        res.status(500).send("Server Error");
    }
});



router.post('/sessions/delete/:id', async (req, res) => {
    const sessionId = req.params.id;

    try {
        
        await pool.query('DELETE FROM session_participants WHERE session_id = $1', [sessionId]);


        await pool.query('DELETE FROM sessions WHERE id = $1', [sessionId]);

        res.redirect('/admin-dashboard');
    } catch (error) {
        console.error("Error deleting session:", error);
        res.redirect('/admin-dashboard');
    }
});

router.get('/change-password',(req,res)=>{
    res.render('change-password');
})

router.post('/change-password', isAuthenticated, async (req, res) => {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;
        const userId = req.session.user.id; 

        
        if (newPassword !== confirmPassword) {
            return res.status(400).send('New passwords do not match');
        }

        
        const result = await pool.query('SELECT password FROM users WHERE id = $1', [userId]);
        
        if (result.rows.length === 0) {
            return res.status(404).send('User not found');
        }

        const currentUserPassword = result.rows[0].password;

        
        const isMatch = await bcrypt.compare(currentPassword, currentUserPassword);
        if (!isMatch) {
            return res.status(400).send('Current password is incorrect');
        }

        
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        
        await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedNewPassword, userId]);

        
        if (req.session.user.role === 'admin') {
            return res.redirect('/admin-dashboard'); 
        } else {
            return res.redirect('/player-dashboard'); 
        }
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).send('Server Error'); 
    }
});

module.exports = router;
