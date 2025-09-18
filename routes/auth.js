const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const wantsJSON = require('../utils/wantsJSON');
const validateRedirect = require('../utils/validateRedirect');
const prisma = require('../utils/prisma');
const isLoggedIn = require('../utils/isLoggedIn');

const router = express.Router();

const JWT_COOKIE_NAME = 'token';
const JWT_TTL = '7d';
const AUTH_LAYOUT = 'layouts/auth';

function signJwt(payload, secret) {
    return jwt.sign(payload, secret, { expiresIn: JWT_TTL });
}

function setAuthCookie(res, token) {
    res.cookie(JWT_COOKIE_NAME, token, {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 dagen
    });
}

// Uniforme helper voor JSON of server-rendered views (voor auth-views altijd AUTH_LAYOUT)
function sendViewOrJson(req, res, status, view, model, jsonBody) {
    if (wantsJSON(req)) {
        return res.status(status).json(jsonBody ?? { error: model?.error || 'Error' });
    }
    return res.status(status).render(view, { layout: AUTH_LAYOUT, ...model });
}

// Helper om token uit te geven en cookie te zetten
function issueSession(res, user) {
    const token = signJwt({ sub: user.id, email: user.email }, process.env.JWT_SECRET);
    setAuthCookie(res, token);
    return token;
}

router.get('/register', async (req, res) => {
    res.render('auth/register',  {
        title: 'Registreren',
        layout: 'layouts/auth',
        error: null,
        values: { email: '' } })
})

router.post('/register', async (req, res) => {
    try {
        const {email, password} = req.body || {};
        if (!email || !password) {
            if (wantsJSON(req)) {
                return res.status(400).json({error: 'Email and password are required.'});
            }
            return res.status(400).render('auth/register', {
                title: 'Register',
                layout: 'layouts/auth',
                error: 'Email and password are required.',
                values: {email: 'email' || ''},
            })
        }
        let existing;
        try{
            existing = await prisma.user.findUnique({where: {email}});
        } catch (err) {
            console.error(err);
            if (wantsJSON(req)) {
                return res.status(409).json({error: 'Error while registering.'});
            }
            return res.status(409).render('auth/register', {
                title: 'Register',
                layout: 'layouts/auth',
                error: 'Error while registering.',
                values: {email: 'email'},
            });
        }
        if (existing) {
            if (wantsJSON(req)) {
                return res.status(409).json({error: 'Email already  in use.'});
            }
            return res.status(409).render('auth/register', {
                title: 'Register',
                layout: 'layouts/auth',
                error: 'Email already  in use.',
                values: {email: 'email'},

            });
        }

        const saltRounds = Number(process.env.BCRYPT_ROUNDS || 12);
        const passwordHash = await bcrypt.hash(password, saltRounds);

        const user = await prisma.user.create({
            data: {email, password: passwordHash},
            select: {id: true, email: true},
        });

        const token = issueSession(res, user);

        if (wantsJSON(req)) {
            return res.status(201).json({ user, token });
        }

        const safeRedirect = validateRedirect(req, req.body.redirect);
        return res.redirect(safeRedirect || '/auth/login?success=true&message=Account%20created%20successfully!');

    } catch (err) {
        console.error(err);
        if (wantsJSON(req)) {
            return res.status(500).json({error: 'Internal server error'});
        }
        return res.status(500).render('auth/register', {
            title: 'Register',
            layout: 'layouts/auth',
            error: 'Error while registering.',
            values: {email: '' || ''},
        });
    }
});


router.get('/login', (req, res) => {
    // Als al ingelogd (geldige token), redirect naar home
    if (isLoggedIn(req)) {
        return res.redirect('/');
    }

    const success = req.query.success === 'true';
    const message = req.query.message || '';

    res.render('auth/login', {
        title: 'Login',
        layout: 'layouts/auth',
        error: null,
        success: success,
        message: message,
        values: { email: '' }
    })
})

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body || {};
        if (!email || !password) {
                return sendViewOrJson(req, res, 400, 'auth/login', {
                    title: 'login',
                    error: 'Email and password are required.',
                    message: '',
                    values: { email: email || '' },
                }, { error: 'Email and password are required.' });
        }

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            if (wantsJSON(req)) {
                return res.status(401).json({error: 'Invalid credentials'});
            } else {
                return res.status(401).render('auth/login', {
                    title: 'login',
                    layout: 'layouts/auth',
                    error: 'Invalid credentials',
                    message: '',
                    values: {email: 'email'},
                })
            }
        }
        const ok = await bcrypt.compare(password, user.password);
        if (!ok) {
            if (wantsJSON(req)) {
                return res.status(401).json({error: 'Invalid credentials'});
            }
            return res.status(401).render('auth/login', {
                title: 'login',
                layout: 'layouts/auth',
                error: 'Invalid credentials',
                message: '',
                values: {email: 'email'},
            })
        }

        const token = issueSession(res, user);

        if (wantsJSON(req)) {
            return res.json({
                user: { id: user.id, email: user.email },
                token,
            });
        } else {
            return res.redirect('/');
        }

    } catch (err) {
        if (wantsJSON(req)) {
            return res.status(500).json({ error: 'Internal server error' });
        } else {
            return res.status(500).render('auth/login', {
                title: 'login',
                layout: 'layouts/auth',
                error: 'Internal server error',
                message: '',
                values: {email: 'email' || ''},
            });
        }
    }
});
router.get('/logout', (req, res) => {
    res.clearCookie(JWT_COOKIE_NAME, {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
    });
    return res.redirect('/auth/login');
})

router.post('/logout', (req, res) => {
    res.clearCookie(JWT_COOKIE_NAME, {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
    });
    return res.status(204).end();
});

module.exports = router;