const express = require('express');
const router = express.Router();
const Medicine = require('../models/Medicine');
const auth = require('../middlewares/auth');
const upload = require('../middlewares/upload');

// 1. Upload a new medicine (default to status "pending")
router.post('/', auth, upload.single('photo'), async (req, res) => {
  try {
    const { name, expiryDate, quantity } = req.body;
    const photoUrl = req.file ? `/uploads/${req.file.filename}` : '';
    const medicine = new Medicine({
      name,
      expiryDate,
      quantity,
      photoUrl,
      donor: req.user.id,
      status: 'pending' // <-- Set status to "pending"!
    });
    await medicine.save();
    res.status(201).json({ message: 'Medicine uploaded', medicine });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 2. Fetch medicines by status (default to "approved" if not specified)
router.get('/', async (req, res) => {
  const { status } = req.query;
  const filter = {};
  filter.status = status || 'approved';
  try {
    const medicines = await Medicine.find(filter)
      .populate('donor', 'name email')
      .sort({ createdAt: -1 });
    res.json(medicines);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch medicines' });
  }
});

// 3. Admin: Approve a medicine (set status to "approved")
router.put('/:id/approve', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Not authorized' });
  try {
    const med = await Medicine.findById(req.params.id);
    if(!med || med.status !== 'pending') {
      return res.status(404).json({ message: 'Medicine not found or not pending' });
    }
    med.status = 'approved';
    await med.save();
    res.json({ message: 'Medicine approved', medicine: med });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 4. Admin: Reject a medicine (set status to "rejected")
router.put('/:id/reject', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Not authorized' });
  try {
    const med = await Medicine.findById(req.params.id);
    if(!med || med.status !== 'pending') {
      return res.status(404).json({ message: 'Medicine not found or not pending' });
    }
    med.status = 'rejected';
    await med.save();
    res.json({ message: 'Medicine rejected', medicine: med });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 5. Donor: Get all medicines uploaded by this donor (donor profile/history)
router.get('/my', auth, async (req, res) => {
  try {
    const myMeds = await Medicine.find({ donor: req.user.id })
      .sort({ createdAt: -1 });
    res.json(myMeds);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch your medicines' });
  }
});

// 6. NGO: Claim a medicine (only possible on status "approved")
router.post('/claim/:id', auth, async (req, res) => {
  try {
    const medicine = await Medicine.findById(req.params.id);
    if (!medicine || medicine.status !== 'approved') {
      return res.status(404).json({ error: 'Medicine not available for claim' });
    }
    medicine.status = 'claimed';
    medicine.claimedBy = req.user.id;
    await medicine.save();
    res.json({ message: 'Medicine claimed successfully' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

module.exports = router;
