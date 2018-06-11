require('dotenv').config();

// dev packages
const morgan = require('morgan');

// constants
const PORT = process.env.PORT || 3001;

// packages
const express = require('express'),
	app = express(),
	bodyParser = require('body-parser'),
	expressSanitizer = require('express-sanitizer'),
	cors = require('cors');

// routes
const { authRoutes } = require('./routes/');

// helper functions
const { errorHandler, errorThrower } = require('./handlers/errors');
const { getLoggedUser } = require('./middleware/auth');

// Log server requests
app.use(morgan('tiny'));

// allow for request with different origin
app.use(cors());

// for testing with postman
app.use(
	bodyParser.urlencoded({
		extended: true
	})
);

app.use(bodyParser.json());

// sanitize all inputs
app.use(expressSanitizer());

// add user id to req.user_id
app.use(getLoggedUser);

// ROUTES //
app.use('/api/auth/', authRoutes);
////////////

// not found, raise 404
app.use(errorThrower);

// general error handler
app.use(errorHandler);

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
