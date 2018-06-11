module.exports.errorHandler = (err, req, res, next) => {
	return res.status(err.status || 500).json({
		error: {
			message: err.message || 'Something went wrong'
		}
	});
};

module.exports.errorThrower = (req, res, next) => {
	const err = new Error('Not Found');
	err.status = 404;
	next(err);
};
