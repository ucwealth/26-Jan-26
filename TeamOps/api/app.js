const express = require('express');
const app = express();

app.use(express.json());

app.get('/status', (req, res) => {
    res.json({
        status: 'Running',
        timeStamp: new Date().toISOString()
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`App running on port ${PORT}`));