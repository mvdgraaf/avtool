module.exports = function wantsJSON(req) {
    if (req.query.response === 'json' || req.body?.response === 'json') return true;
    if (req.get('X-API-Request') === 'true') return true;

    const accept = req.get('Accept') || '';
    return accept.includes('application/json') && !accept.includes('text/html');
}