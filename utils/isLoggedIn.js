'use strict';

const jwt = require('jsonwebtoken');

const JWT_COOKIE_NAME = 'token';

function getTokenFromReq(req) {
  const auth = req?.headers?.authorization || '';
  const bearer = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const cookieToken = req?.cookies ? req.cookies[JWT_COOKIE_NAME] : null;
  return bearer || cookieToken || null;
}

function isLoggedIn(req) {
  const token = getTokenFromReq(req);
  if (!token) return false;
  try {
    jwt.verify(token, process.env.JWT_SECRET);
    return true;
  } catch {
    return false;
  }
}

module.exports = isLoggedIn;
