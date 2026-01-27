const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const sequelize = require('./common/database');
const defineUser = require('./common/models/User');
const User = defineUser(sequelize);

const encryptPassword = (password) => 
    crypto.createHash('sha256').update(password).digest('hex');

