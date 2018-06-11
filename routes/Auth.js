const router = require('express').Router({ mergeParams: true });

const { signup, signin } = require('../handlers/auth');

router.post('/signup', signup);

router.post('/signin', signin);

module.exports = router;
