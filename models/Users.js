const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const usersSchema = new Schema({
	fullName: String,
    mobileNumber: String,

	email: String,
	password: String,
	refreshToken: String,
	pushToken: String,
	
	sms1: String,
	sms2: String
});

const Users = mongoose.model('Users', usersSchema, 'Users');

module.exports = Users;
