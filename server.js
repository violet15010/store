const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// 中间件
app.use(cors({
    origin: '*',  // 允许所有来源
    methods: ['GET', 'POST'],
    credentials: true
}));
app.use(express.json());

// 数据库连接配置
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',  // 确保这是你的 MySQL 用户名
    password: '123456',  // 确保这是你的 MySQL 密码
    database: 'login_system'
});

// 添加数据库连接错误处理
db.connect((err) => {
    if (err) {
        console.error('数据库连接错误:', err);
        return;
    }
    console.log('数据库连接成功');
});

db.on('error', (err) => {
    console.error('数据库错误:', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        // 重新连接数据库
        db.connect();
    }
});

// 注册接口
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // 检查用户名是否已存在
        db.query('SELECT id FROM users WHERE username = ?', [username], async (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: '服务器错误' });
            }

            if (results.length > 0) {
                return res.status(400).json({ message: '用户名已存在' });
            }

            // 密码加密
            const hashedPassword = await bcrypt.hash(password, 10);

            // 插入新用户
            db.query(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                [username, hashedPassword],
                (err, result) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).json({ message: '注册失败' });
                    }
                    res.status(201).json({ message: '注册成功' });
                }
            );
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 登录接口
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // 查询用户
        db.query(
            'SELECT * FROM users WHERE username = ?',
            [username],
            async (err, results) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ message: '服务器错误' });
                }

                if (results.length === 0) {
                    return res.status(401).json({ message: '用户名或密码错误' });
                }

                const user = results[0];

                // 验证密码
                const validPassword = await bcrypt.compare(password, user.password);
                if (!validPassword) {
                    return res.status(401).json({ message: '用户名或密码错误' });
                }

                // 生成 JWT token
                const token = jwt.sign(
                    { id: user.id, username: user.username },
                    'your_jwt_secret',  // 替换为你的密钥
                    { expiresIn: '24h' }
                );

                res.json({
                    message: '登录成功',
                    token,
                    user: {
                        id: user.id,
                        username: user.username
                    }
                });
            }
        );
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 在 server.js 中添加测试代码
app.get('/test', (req, res) => {
    res.json({ message: '服务器正常运行' });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`服务器运行在 http://localhost:${PORT}`);
}); 