const express = require('express');
const app = express();
app.use(express.json());

const sequelize = require('./common/database');
const defineUser = require('./common/models/User');
const User = defineUser(sequelize);
sequelize.sync()

const authRoutes = require('./auth/routes');
app.use('/', authRoutes);

app.get('/status', (req, res) => {
    res.json({
        status: 'Running',
        timeStamp: new Date().toISOString()
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`App running on port ${PORT}`));