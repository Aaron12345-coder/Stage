const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const { json } = require('body-parser');

dotenv.config();
const PORT = 5000;

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const authenticateToken = (req,res,next)=>{
    const authHeader =req.headers['authorization'];
    const token = authHeader && authHeader.split('')[1];
    if(!token) return res.status(401).json({message:'unauthorized'})
    jwt.verify(token.process.env.JWT_SECRET,(err,user) =>{
        if(err) return res.status(403).json({message:'forbidden'})
        req.user = user
    next()
    });
}


const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('✅ Database connected successfully');
});

app.listen(PORT, () => {
    console.log(`🚀 Server is running on http://localhost:${PORT}`);
});

// ✅ Fixed endpoint URL by adding '/'
app.get('/', (req, res) => {
    res.status(200).json({ message: 'Aaron, Naike, Jack' });
});

// ✅ Fixed API to register a user
app.post('/api/auth/register', async (req, res) => {
    try {
        let { username, email, password } = req.body;

        if (!username || !email || !password) {  // ✅ Fixed OR condition
            return res.status(400).json({ message: 'All fields are required' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        let insertQuery = `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`;

        db.query(insertQuery, [username, email, hashedPassword], (err, result) => {
            if (err) {
                return res.status(500).json({ message: 'Database error', error: err.message });
            }
            res.status(201).json({ message: 'User registered successfully' });
        });

    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// ✅ Fixed Login API
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {  // ✅ Fixed OR condition
            return res.status(400).json({ message: 'All fields are required' });
        }

        db.query('SELECT * FROM users WHERE username = ?', [username], async (err, result) => {
            if (err) {
                return res.status(500).json({ message: 'Database error', error: err.message });
            }

            if (result.length === 0) {
                return res.status(401).json({ message: 'Invalid username or password' });
            }

            const user = result[0];

            const validPassword = await bcrypt.compare(password, user.password);  // ✅ Fixed bcrypt.compare()
            if (!validPassword) {
                return res.status(401).json({ message: 'Invalid username or password' });
            }

            const token = jwt.sign(
                { id: user.id, username: user.username },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }  // ✅ Fixed expiresIn case
            );

            res.status(200).json({ message: 'Login successfully', token });
        });

    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});
app.get("/api/users/:id", authenticateToken , (req,res) => {
    try{
        let id =req.params.id
        db.query("SELECT * FROM users WHERE id = ?",[id],(err,results) => {
            if (err) throw err;
            res.status(200).json(results)
        });
    }catch(err){
        throw err;
        res.status(500),json({message:'server error',error: err.message})
    }
});


