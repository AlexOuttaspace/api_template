const db = require('../models'),
	jwt = require('jsonwebtoken');

const invalidPass = {
	status: 400,
	message: 'Invalid email/password'
};

module.exports.signup = async function(req, res, next) {
	try {
		console.log(req.body);
		const user = await db.User.create(req.body);
		const userData = prepareUserData(user);
		return res.status(200).json(userData);
	} catch (err) {
		if (err.name === 'ValidationError') {
			return next({
				status: 400,
				message: 'Invalid input'
			});
		}
		if (err.code === 11000) {
			err.message = 'User with this email is already registered';
		}
		return next(err);
	}
};

module.exports.signin = async function(req, res, next) {
	try {
		const user = await db.User.findOne({ email: req.body.email });

		const validPassword = await user.comparePassword(req.body.password);

		if (validPassword) {
			const userData = prepareUserData(user);
			return res.status(200).json(userData);
		} else {
			next(invalidPass);
		}
	} catch (err) {
		next(invalidPass);
	}
};

const prepareUserData = ({
	_id,
	username,
	profileImageUrl,
	likedPosts,
	likedComments
}) => {
	const token = jwt.sign(
		{
			_id,
			username,
			profileImageUrl
		},
		process.env.SECRET_KEY
	);

	return {
		_id,
		username,
		profileImageUrl,
		likedPosts,
		likedComments,
		token
	};
};
