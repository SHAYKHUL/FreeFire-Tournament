const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();

const SECRET = '1234';

const db = new sqlite3.Database('freefire.sqlite');

// Initialize tables
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      passwordHash TEXT,
      role TEXT,
      walletBalance INTEGER
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS matches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category TEXT,
      format TEXT,
      map TEXT,
      entryFee INTEGER,
      prizePool INTEGER,
      scheduledAt DATETIME,
      status TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS match_players (
      matchId INTEGER,
      userId INTEGER,
      UNIQUE (matchId, userId)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS match_results (
      matchId INTEGER,
      userId INTEGER,
      rank INTEGER,
      prize INTEGER
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS join_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      matchId INTEGER,
      userId INTEGER,
      status TEXT DEFAULT 'pending',
      requestedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      userUniqueId TEXT,
      phoneNumber TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS match_rooms (
      matchId INTEGER PRIMARY KEY,
      roomDetails TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS announcements (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      message TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// Default admin credentials
const defaultAdmin = {
  username: 'admin',
  email: 'admin@example.com',
  password: 'admin1234',
  role: 'admin',
  walletBalance: 0,
};

// Create default admin if not exists
db.get('SELECT * FROM users WHERE email = ?', [defaultAdmin.email], async (err, row) => {
  if (err) {
    console.error('Error checking admin user:', err);
    return;
  }
  if (!row) {
    const passwordHash = await bcrypt.hash(defaultAdmin.password, 10);
    db.run(
      `INSERT INTO users (username, email, passwordHash, role, walletBalance) VALUES (?,?,?,?,?)`,
      [defaultAdmin.username, defaultAdmin.email, passwordHash, defaultAdmin.role, defaultAdmin.walletBalance],
      (err) => {
        if (err) {
          console.error('Error creating default admin:', err);
        } else {
          console.log('Default admin created: email =', defaultAdmin.email, 'password =', defaultAdmin.password);
        }
      }
    );
  } else {
    console.log('Default admin already exists');
  }
});

// Express App
const app = express();
app.use(cors());
app.use(express.json());

// Auth Middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Missing token' });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Signup
app.post('/api/auth/signup', async (req, res) => {
  const { username, email, password, role } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ message: 'All fields required' });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  db.run(
    `INSERT INTO users (username, email, passwordHash, role, walletBalance) VALUES (?,?,?,?,?)`,
    [username, email, passwordHash, role || 'player', 500],
    function (err) {
      if (err) return res.status(400).json({ message: 'Username or email already in use' });

      const token = jwt.sign({ id: this.lastID, role: role || 'player' }, SECRET);
      res.json({ token });
    }
  );
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, row) => {
    if (err || !row) return res.status(400).json({ message: 'Invalid credentials' });

    if (await bcrypt.compare(password, row.passwordHash)) {
      const token = jwt.sign({ id: row.id, role: row.role }, SECRET);
      res.json({ token });
    } else {
      res.status(400).json({ message: 'Invalid credentials' });
    }
  });
});

// Create match (admin only)
app.post('/api/matches', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });

  const { category, format, map, entryFee, prizePool, scheduledAt } = req.body;

  db.run(
    `INSERT INTO matches (category, format, map, entryFee, prizePool, scheduledAt, status) VALUES (?,?,?,?,?,?,?)`,
    [category, format, map, entryFee, prizePool, scheduledAt, 'scheduled'],
    function (err) {
      if (err) {
        console.error('Error inserting match:', err);
        return res.status(500).json({ message: 'Server Error', error: err.message });
      }
      res.json({ matchId: this.lastID });
    }
  );
});

// Get all upcoming matches/tournaments
app.get('/api/matches/upcoming', auth, (req, res) => {
  const sql = `SELECT * FROM matches WHERE status = 'scheduled' ORDER BY scheduledAt ASC`;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Server Error' });
    res.json(rows);
  });
});

// Get all past matches/tournaments with player count
app.get('/api/matches/past', auth, (req, res) => {
  const sql = `
    SELECT m.*, 
      (SELECT COUNT(*) FROM match_results mr WHERE mr.matchId = m.id) AS playersCount
    FROM matches m WHERE m.status = 'completed' ORDER BY m.scheduledAt DESC
  `;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Server Error' });
    res.json(rows);
  });
});

// Get match/tournament details with leaderboard
app.get('/api/matches/:id/details', auth, (req, res) => {
  const matchId = parseInt(req.params.id);

  db.get('SELECT * FROM matches WHERE id = ?', [matchId], (err, match) => {
    if (err || !match) return res.status(404).json({ message: 'Match not found' });

    db.all(
      `SELECT mr.rank, mr.prize, u.username FROM match_results mr
       JOIN users u ON mr.userId = u.id WHERE mr.matchId = ? ORDER BY mr.rank ASC`,
      [matchId],
      (err, results) => {
        if (err) return res.status(500).json({ message: 'Server Error' });

        res.json({
          match,
          leaderboard: results,
        });
      }
    );
  });
});

// Player requests to join a match (pending admin approval)
app.post('/api/matches/:id/request-join', auth, (req, res) => {
  const matchId = parseInt(req.params.id);
  const userId = req.user.id;
  const { userUniqueId, phoneNumber } = req.body;

  db.get('SELECT * FROM matches WHERE id = ?', [matchId], (err, match) => {
    if (err || !match) return res.status(404).json({ message: 'Match not found' });

    db.get(
      'SELECT * FROM join_requests WHERE matchId = ? AND userId = ?',
      [matchId, userId],
      (err, existingRequest) => {
        if (existingRequest)
          return res.status(400).json({ message: 'Join request already submitted' });

        db.run(
          'INSERT INTO join_requests (matchId, userId, userUniqueId, phoneNumber) VALUES (?, ?, ?, ?)',
          [matchId, userId, userUniqueId, phoneNumber],
          (err) => {
            if (err) return res.status(500).json({ message: 'Server Error' });
            res.json({ message: 'Join request submitted. Await admin confirmation.' });
          }
        );
      }
    );
  });
});

// Admin views all pending join requests
app.get('/api/admin/join-requests', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });

  db.all(
    `SELECT jr.id, jr.matchId, jr.userId, jr.status, jr.requestedAt, jr.userUniqueId, jr.phoneNumber, u.username, m.category, m.format 
     FROM join_requests jr
     JOIN users u ON jr.userId = u.id
     JOIN matches m ON jr.matchId = m.id
     WHERE jr.status = 'pending'`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ message: 'Server Error' });
      res.json(rows);
    }
  );
});

// Admin approves or rejects join request, adds room details if approved
app.post('/api/admin/join-requests/:id/decision', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });

  const joinRequestId = parseInt(req.params.id);
  const { decision, roomDetails } = req.body;

  if (!['approved', 'rejected'].includes(decision)) {
    return res.status(400).json({ message: 'Invalid decision' });
  }

  db.get('SELECT * FROM join_requests WHERE id = ?', [joinRequestId], (err, jr) => {
    if (err || !jr) return res.status(404).json({ message: 'Join request not found' });

    db.run('UPDATE join_requests SET status = ? WHERE id = ?', [decision, joinRequestId], (err) => {
      if (err) return res.status(500).json({ message: 'Server Error' });

      if (decision === 'approved') {
        db.run(
          `INSERT INTO match_rooms (matchId, roomDetails) VALUES (?, ?)
           ON CONFLICT(matchId) DO UPDATE SET roomDetails=excluded.roomDetails`,
          [jr.matchId, roomDetails || 'Details pending'],
          (err) => {
            if (err) return res.status(500).json({ message: 'Server Error' });
            res.json({ message: 'Join request approved and room details saved' });
          }
        );
      } else {
        res.json({ message: 'Join request rejected' });
      }
    });
  });
});

// Player fetches their approved joined matches + room details
app.get('/api/users/me/joined-matches', auth, (req, res) => {
  const userId = req.user.id;

  db.all(
    `SELECT m.*, mr.roomDetails
     FROM join_requests jr
     JOIN matches m ON jr.matchId = m.id
     LEFT JOIN match_rooms mr ON m.id = mr.matchId
     WHERE jr.userId = ? AND jr.status = 'approved'`,
    [userId],
    (err, rows) => {
      if (err) return res.status(500).json({ message: 'Server Error' });
      res.json(rows);
    }
  );
});

// View wallet balance (for user or admin)
app.get('/api/users/:id/wallet', auth, (req, res) => {
  if (parseInt(req.params.id) !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Forbidden' });
  }
  db.get('SELECT walletBalance FROM users WHERE id = ?', [req.params.id], (err, row) => {
    if (err || !row) return res.status(404).json({ message: 'User not found' });

    res.json({ walletBalance: row.walletBalance });
  });
});

// View match results (for user or admin)
app.get('/api/users/:id/results', auth, (req, res) => {
  if (parseInt(req.params.id) !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Forbidden' });
  }
  db.all('SELECT * FROM match_results WHERE userId = ?', [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Server Error' });

    res.json(rows);
  });
});

// Submit match results (admin only)
app.post('/api/matches/:id/results', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });

  const matchId = parseInt(req.params.id);
  const results = req.body.results; // [{userId, rank, prize}, ...]

  db.run('UPDATE matches SET status = "completed" WHERE id = ?', [matchId]);

  results?.forEach((r) => {
    db.run(
      'INSERT INTO match_results (matchId, userId, rank, prize) VALUES (?,?,?,?)',
      [matchId, r.userId, r.rank, r.prize],
      (err) => {
        if (err) console.error(err);
      }
    );
    db.run(
      'UPDATE users SET walletBalance = walletBalance + ? WHERE id = ?',
      [r.prize, r.userId],
      (err) => {
        if (err) console.error(err);
      }
    );
  });

  res.json({ message: 'Results submitted and prizes distributed' });
});

// Get player profile (self or admin)
app.get('/api/users/:id/profile', auth, (req, res) => {
  const userId = parseInt(req.params.id);
  if (userId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Forbidden' });
  }
  db.get('SELECT id, username, email, role, walletBalance FROM users WHERE id = ?', [userId], (err, row) => {
    if (err || !row) return res.status(404).json({ message: 'User not found' });
    res.json(row);
  });
});

// Admin posts a new announcement
app.post('/api/announcements', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const { message } = req.body;
  if (!message) return res.status(400).json({ message: 'Message required' });
  db.run(
    'INSERT INTO announcements (message) VALUES (?)',
    [message],
    function (err) {
      if (err) return res.status(500).json({ message: 'Server Error' });
      res.json({ id: this.lastID, message });
    }
  );
});

// All users fetch latest announcements (public, no auth)
app.get('/api/announcements', (req, res) => {
  db.all('SELECT * FROM announcements ORDER BY createdAt DESC LIMIT 10', [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Server Error' });
    res.json(rows);
  });
});

// Start server
const port = 5000;
app.listen(port, () => console.log(`Server listening on port ${port}`));
