const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  secretQuestion: { type: String, required: true },
  secretAnswerHash: { type: String, required: true }
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
