var express = require('express');
var router = express.Router();
const getGravatarUrl = require("../utils/gravatar")
const getUser= require("../utils/getUser")

/* GET home page. */
router.get('/', function(req, res) {
  res.render('index', {
      title: 'Express',
      gravatar: getGravatarUrl(getUser(req).email || "test@test.nl")
  });
});

module.exports = router;
``