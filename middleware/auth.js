const jwt = require('jsonwebtoken');

const notLoginErr = {
	status: 401,
	message: 'Please log in first'
};

const notAuthErr = {
	status: 401,
	message: 'Unauthorized'
};

// make sure user is logged in
exports.loginRequired = function(req, res, next) {
	if (req.user_id) {
		return next();
	} else {
		return next(notLoginErr);
	}
};

// makes sure request comes from correct user
exports.ensureCorrectUser = function(req, res, next) {
	if (req.user_id === req.params.user_id) {
		return next();
	} else {
		next(notAuthErr);
	}
};

// check if user logged in, if so add user id to req.user
exports.getLoggedUser = function(req, res, next) {
	try {
		if (req.headers.authorization) {
			// get token from header
			const token = req.headers.authorization.split(' ')[1];

			jwt.verify(token, process.env.SECRET_KEY, function(err, decoded) {
				if (decoded) {
					req.user_id = decoded._id;
					return next();
				}
				return next(notLoginErr);
			});
		} else {
			return next();
		}
	} catch (e) {
		next(notLoginErr);
	}
};
