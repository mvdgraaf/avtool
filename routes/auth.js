const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const router = express.Router();

const JWT_COOKIE_NAME = 'token';
const JWT_TTL = '7d';

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

function wantsJSON(req) {
    if (req.query.response === 'json' || req.body?.response === 'json') return true;
    if (req.get('X-API-Request') === 'true') return true;

    const accept = req.get('Accept') || '';
    return accept.includes('application/json') && !accept.includes('text/html');
}

function validateRedirect(req,redirectParam) {
    if (!redirectParam) return null;

    if (redirectParam.startsWith('/')) {
        return redirectParam;
    }
    try {
        const url = new URL(redirectParam);
        if (!['http:', 'https:'].includes(url.protocol)) {return redirectParam;}

        const allowedHosts = (process.env.ALLOWED_REDIRECT_HOSTS || '').split(',').map(h => h.trim()).filter(Boolean);
        if (allowedHosts.length === 0) {return null;}
        if (allowedHosts.includes(url.hostname)) {return url.toString();}
        return null;
    } catch (_e) {
        return null;
    }
}

router.get('/register', async (req, res) => {
    res.render('auth/register',  { title: 'Registreren', error: null, values: { email: '' } })
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
                error: 'Email and password are required.',
                values: {email: 'email' || ''},
            })
        }

        const existing = await prisma.user.findUnique({where: {email}});
        if (existing) {
            if (wantsJSON(req)) {
                return res.status(409).json({error: 'Email already  in use.'});
            }
            return res.status(409).render('auth/register', {
                title: 'Register',
                error: 'Email already in use.',
                values: {email: 'email'},

            });
        }

        const saltRounds = Number(process.env.BCRYPT_ROUNDS || 12);
        const passwordHash = await bcrypt.hash(password, saltRounds);

        const user = await prisma.user.create({
            data: {email, password: passwordHash},
            select: {id: true, email: true},
        });

        const token = signJwt({sub: user.id, email: user.email}, process.env.JWT_SECRET);
        setAuthCookie(res, token);

        if (wantsJSON(req)) {
            return res.status(201).json({user, token});
        }

        const safeRedirect = validateRedirect(req, req.body.redirect);
        return res.redirect(safeRedirect || '/login?success=true&message=Account%20created%20successfully!');

    } catch (err) {
        if (wantsJSON(req)) {
            return res.status(500).json({error: 'Internal server error'});
        }
        return res.status(500).render('auth/register', {
            title: 'Register',
            error: 'Internal server error',
            values: {email: 'email' || ''},
        });
    }
});


router.get('/login', (req, res) => {
    const success = req.query.success === 'true';
    const message = req.query.message || '';

    res.render('auth/login', { title: 'Login', error: null, success: success, message: message, values: { email: '' } })
})

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body || {};
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required.' });
        }

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });

        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

        const token = signJwt({ sub: user.id, email: user.email }, process.env.JWT_SECRET);
        setAuthCookie(res, token);

        return res.json({
            user: { id: user.id, email: user.email },
            token,
        });
    } catch (err) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/logout', (req, res) => {
    res.clearCookie(JWT_COOKIE_NAME, {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
    });
    return res.status(204).end();
});

module.exports = router;