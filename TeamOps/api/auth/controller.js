const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const sequelize = require('./common/database');
const defineUser = require('./common/models/User');
const User = defineUser(sequelize);

const encryptPassword = (password) => 
    crypto.createHash('sha256').update(password).digest('hex');

const generateAccessToken = (username, userId) => 
    jwt.sign({ username, userId }, 'your-secret-key', { expiresIn: '24h' });

exports.register = async (req, res) => {
    try {
        const { username, email, password, firstname, lastname, age } = req.body;
        const encryptedPassword = encryptPassword(password);
        const user = await User.create({ 
            username, email, password: encryptedPassword, 
            firstname, lastname, age 
        })
        const accessToken = generateAccessToken(username, userId);
        res.status(201).json({
            success: true,
            user: { id: user.userId, username: user.username, email: user.email },
            token, accessToken
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            error: err.message
        });
    }

};