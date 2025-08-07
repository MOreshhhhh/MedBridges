// routes/admin.js
const express = require('express');
const router = express.Router();

const User = require('../models/User');
const Medicine = require('../models/Medicine');
const logAction = require('../middlewares/actionLogger');
const auth = require('../middlewares/auth');         // JWT auth middleware
const requireAdmin = require('../middlewares/admin'); // Role admin check middleware


// ---------------------------------------
// USER ROUTES
// ---------------------------------------

// GET all users, optional filter by role and sort
router.get('/users', auth, requireAdmin, async (req, res) => {
  try {
    const { role, sort } = req.query;
    const filter = role ? { role } : {};
    const users = await User.find(filter)
      .sort(sort || '-createdAt')
      .select('-password'); // exclude password
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// PUT update user fields
router.put('/users/:id', auth, requireAdmin, async (req, res) => {
  const { verified, isBlocked, name, email, role } = req.body;
  const updates = {};
  if (typeof verified === 'boolean') updates.verified = verified;
  if (typeof isBlocked === 'boolean') updates.isBlocked = isBlocked;
  if (name) updates.name = name;
  if (email) updates.email = email;
  if (role) updates.role = role;

  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const oldUser = user.toObject();
    Object.assign(user, updates);
    await user.save();

    // Log changed fields only
    const changedFields = {};
    for (const key in updates) {
      if (oldUser[key] !== updates[key]) {
        changedFields[key] = { before: oldUser[key], after: updates[key] };
      }
    }
    if (Object.keys(changedFields).length > 0) {
      await logAction(req.user.id, 'update_user', { userId: user._id, changes: changedFields });
    }

    const userObj = user.toObject();
    delete userObj.password;

    res.json({ message: 'User updated', user: userObj });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// PATCH block or unblock a user
router.patch('/users/:id/block', auth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { isBlocked } = req.body;

    if (typeof isBlocked !== 'boolean') {
      return res.status(400).json({ message: 'isBlocked boolean is required' });
    }

    const user = await User.findById(id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.isBlocked === isBlocked) {
      return res.status(400).json({ message: `User already ${isBlocked ? 'blocked' : 'unblocked'}` });
    }

    user.isBlocked = isBlocked;
    await user.save();

    await logAction(req.user.id, 'block_user', { blockedUserId: id, isBlocked });

    res.json({ message: `User ${isBlocked ? 'blocked' : 'unblocked'} successfully` });
  } catch (error) {
    console.error('Error updating user block status:', error);
    res.status(500).json({ message: 'Failed to update user block status', error: error.message });
  }
});

// ---------------------------------------
// MEDICINE ROUTES
// ---------------------------------------

// GET all medicines with donor and claimedBy info
router.get('/medicines', auth, requireAdmin, async (req, res) => {
  try {
    const medicines = await Medicine.find()
      .populate('donor', 'name email')
      .populate('claimedBy', 'name email')
      .sort('-uploadedAt');
    res.json(medicines);
  } catch (error) {
    console.error('Error fetching medicines:', error);
    res.status(500).json({ error: 'Failed to fetch medicines' });
  }
});

// PUT update medicine fields
router.put('/medicines/:id', auth, requireAdmin, async (req, res) => {
  const { name, expiry, quantity, status, verified, isBlocked } = req.body;
  const updates = {};
  if (name) updates.name = name;
  if (expiry) updates.expiry = expiry;
  if (typeof quantity === 'number') updates.quantity = quantity;
  if (status) updates.status = status;
  if (typeof verified === 'boolean') updates.verified = verified;
  if (typeof isBlocked === 'boolean') updates.isBlocked = isBlocked;

  try {
    const medicine = await Medicine.findById(req.params.id);
    if (!medicine) return res.status(404).json({ error: 'Medicine not found' });

    const oldMedicine = medicine.toObject();
    Object.assign(medicine, updates);
    await medicine.save();

    // Log changed fields only
    const changedFields = {};
    for (const key in updates) {
      if (oldMedicine[key] !== updates[key]) {
        changedFields[key] = { before: oldMedicine[key], after: updates[key] };
      }
    }
    if (Object.keys(changedFields).length > 0) {
      await logAction(req.user.id, 'update_medicine', {
        medicineId: medicine._id,
        changes: changedFields,
      });
    }

    res.json({ message: 'Medicine updated', medicine });
  } catch (error) {
    console.error('Error updating medicine:', error);
    res.status(500).json({ error: 'Failed to update medicine' });
  }
});

module.exports = router;
