const crypto = require('crypto');

module.exports = function getGravatarUrl(email) {
    const trimmedEmail = email.trim().toLowerCase();
    console.log(trimmedEmail);
    const hash = crypto.createHash('sha256').update(trimmedEmail).digest('hex');
    return `https://www.gravatar.com/avatar/${hash}`;
};