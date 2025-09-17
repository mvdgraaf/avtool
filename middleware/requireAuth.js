const jwt = require('jsonwebtoken');
const wantsJSON = require('./wantsJSON');

module.exports = function requireAuth(req, res, next) {
    try {
        const auth = req.headers.authorization || '';
        const bearer = auth.startsWith('Bearer ') ? auth.slice(7) : null;
        const cookieToken = req.cookies ? req.cookies.token : null;
        const token = bearer || cookieToken;
        if (!token) {
            if (wantsJSON(req)) {
                return res.status(401).json({ error: 'You are not authenticated.' });
            } else {
                return res.redirect('/auth/login');
            }
        }
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.user = { id: payload.sub, email: payload.email };
        next();
    } catch (err) {
        if (wantsJSON(req)) {
            return res.status(401).json({ error: 'Invalid or expired token.' });
        } else {
            return res.status(401).render('auth/login', {
                title: 'Login',
                error: 'Invalid or expired token.',
                values: { email: '' },
            });
        }
    }
};