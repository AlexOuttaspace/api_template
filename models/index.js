const mongoose = require('mongoose');

mongoose.set('debug', true);

mongoose.connect(process.env.DB_URL);

mongoose.connection
	.once('open', () => {
		console.log('Connected to database');
	})
	.on('error', (error) => {
		console.warn('Mongoose error:', error);
	});

module.exports.User = require('./User');
