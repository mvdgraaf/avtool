const jwt = require('jsonwebtoken');

module.exports = function requireAuth(req, res, next) {
    try {
        const auth = req.headers.authorization || '';
        const bearer = auth.startsWith('Bearer ') ? auth.slice(7) : null;
        const cookieToken = req.cookies ? req.cookies.token : null;
        const token = bearer || cookieToken;
        if (!token) return res.status(401).json({ error: 'You are not authenticated.' });

        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.user = { id: payload.sub, email: payload.email };
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token.' });
    }
};