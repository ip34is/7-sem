const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
const port = 3000;

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SECRET_KEY = 'secret_jwt_key';

app.use((req, res, next) => {
    let token = req.headers['authorization'];

    if (token) {
        if (token.startsWith('Bearer ')) {
            token = token.slice(7);
        }

        jwt.verify(token, SECRET_KEY, (err, user) => {
            if (!err) {
                req.session = user;
            } else {
                req.session = {};
            }
            next();
        });
    } else {
        req.session = {};
        next();
    }
});

app.get('/', (req, res) => {
    if (req.session && req.session.username) {
        return res.json({
            username: req.session.username,
            logout: 'http://localhost:3000/logout'
        });
    }
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/logout', (req, res) => {
    res.redirect('/');
});

const users = [
    {
        login: 'Login',
        password: 'Password',
        username: 'Username',
    },
    {
        login: 'Login1',
        password: 'Password1',
        username: 'Username1',
    }
];

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;

    const user = users.find((user) => user.login === login && user.password === password);

    if (user) {
        const token = jwt.sign({ username: user.username, login: user.login }, SECRET_KEY, { expiresIn: '1h' });
        return res.json({ token });
    }

    res.status(401).send();
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});