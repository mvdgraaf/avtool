module.exports = function validateRedirect(req,redirectParam) {
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