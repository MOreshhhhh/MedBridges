const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const auth = require('../middlewares/auth');

// Register Route
router.post('/register', async (req, res) => {
  const { name, email, password, role, contact } = req.body;

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Hash password before saving
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({ name, email, password: hashedPassword, role, contact });
    await user.save();
    return res.json({ message: 'Registered successfully!' });
  } catch (err) {
    console.error('Registration error:', err);
    return res.status(400).json({ error: 'Invalid data or registration failed' });
  }
});

// Login Route
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      // Avoid saying which part failed for security  
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Create JWT token signed with user id and role
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: '7d', // optional expiry
    });

    return res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Server error during login' });
  }
});

// Get current logged-in user profile
router.get('/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json(user);
  } catch (err) {
    console.error('Fetch current user error:', err);
    return res.status(500).json({ message: 'Failed to fetch user profile' });
  }
});

// Update current user profile
router.put('/me', auth, async (req, res) => {
  const allowed = ['name', 'email', 'contact'];
  const updates = {};

  allowed.forEach(field => {
    if (req.body[field]) updates[field] = req.body[field];
  });

  try {
    // Handle password update separately with hashing
    if (req.body.password) {
      const salt = await bcrypt.genSalt(10);
      updates.password = await bcrypt.hash(req.body.password, salt);
    }

    const user = await User.findByIdAndUpdate(
      req.user.id,
      updates,
      { new: true, runValidators: true }
    ).select('-password');

    if (!user) return res.status(404).json({ message: 'User not found' });

    return res.json({ message: 'Profile updated', user: user.toObject() });
  } catch (err) {
    console.error('Update profile error:', err);
    return res.status(400).json({ error: err.message });
  }
});

module.exports = router;
