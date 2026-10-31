'use strict';

const express = require('express');
const { arkenAuth } = require('@arkenforge/arken-auth');

const app = express();

app.get('/', (req, res) => {
    res.json({ message: 'Arken Protocol — Express example' });
});

// Protected route — requires a valid a401 signature
app.get('/protected', arkenAuth(), (req, res) => {
    res.json({
        message: 'Authenticated',
        did: req.user.did,
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Protected endpoint: http://localhost:${PORT}/protected`);
});
