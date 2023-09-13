const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const childSchema = new Schema({
	name: String,
	bandId: String,
	activationCode: String,
	userId : String,
    path: String,
    pathurl: String
});

const Child = mongoose.model('Child', childSchema, 'Child');

module.exports = Child;
