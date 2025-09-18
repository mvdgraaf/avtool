module.exports = function getUser(req) {

    const user = req.user;
    console.log(user);
    return {
        id: user?.id,
        email: user?.email,
    };
}