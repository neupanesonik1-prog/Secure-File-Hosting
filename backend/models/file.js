const mongoose = require('mongoose');
module.exports = mongoose.model('File', new mongoose.Schema({
  filename: String,
  originalName: String,
  path: String,
  size: Number,
  privacy: { type: String, enum: ['public', 'private'], default: 'public' },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  uploadedAt: { type: Date, default: Date.now }
}));