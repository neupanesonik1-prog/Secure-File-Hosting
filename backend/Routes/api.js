const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const auth = require('../middleware/auth');
const User = require('../models/User');
const File = require('../models/File');

// MULTER
const upload = multer({
  dest: '../uploads/',
  limits: { fileSize: 20*1024*1024 },
  fileFilter: (req, file, cb) => {
    if (!file.originalname.match(/\.(pdf|mp4)$/i)) 
      return cb(new Error('Only PDF & MP4'));
    cb(null, true);
  }
});

// REGISTER & LOGIN
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    if (await User.findOne({ email })) return res.status(400).json({ msg: 'Email exists' });
    const user = new User({ username, email, password: bcrypt.hashSync(password, 10) });
    await user.save();
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (e) { res.status(500).json({ msg: 'Error' }); }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(400).json({ msg: 'Wrong email/password' });
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

// FILE ROUTES
router.post('/upload', auth, upload.single('file'), async (req, res) => {
  const file = new File({
    filename: req.file.filename,
    originalName: req.file.originalname,
    path: req.file.path,
    size: req.file.size,
    privacy: req.body.privacy || 'public',
    uploadedBy: req.user.id
  });
  await file.save();
  res.json({ msg: 'Uploaded!', file });
});

router.get('/myfiles', auth, async (req, res) => {
  const files = await File.find({ uploadedBy: req.user.id }).sort('-uploadedAt');
  res.json(files);
});

router.get('/public', async (req, res) => {
  const files = await File.find({ privacy: 'public' }).sort('-uploadedAt');
  res.json(files);
});

router.get('/download/:id', async (req, res) => {
  const file = await File.findById(req.params.id);
  if (!file) return res.status(404).send('Not found');
  if (file.privacy === 'private') {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).send();
    try { jwt.verify(token, process.env.JWT_SECRET); }
    catch { return res.status(401).send(); }
  }
  res.download(file.path, file.originalName);
});

router.delete('/:id', auth, async (req, res) => {
  const file = await File.findById(req.params.id);
  if (file.uploadedBy.toString() !== req.user.id) return res.status(403).send();
  fs.unlinkSync(file.path);
  await file.deleteOne();
  res.json({ msg: 'Deleted' });
});

module.exports = router;