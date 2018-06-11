const mongoose = require('mongoose'),
	bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
	email: {
		type: String,
		required: true,
		unique: true
	},
	username: {
		type: String,
		required: true
	},
	password: {
		type: String,
		required: true
	},
	profileImageUrl: {
		type: String
	}
});

userSchema.pre('save', async function(next) {
	try {
		if (this.isModified('password')) {
			this.password = await bcrypt.hash(
				this.password,
				+process.env.SALTROUNDS
			);
		}
		return next();
	} catch (err) {
		return next(err);
	}
});

userSchema.methods.comparePassword = async function(candidatePassword, next) {
	try {
		const isMatch = await bcrypt.compare(candidatePassword, this.password);
		return isMatch;
	} catch (err) {
		return next(err);
	}
};

module.exports = mongoose.model('User', userSchema);
