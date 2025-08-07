const express = require('express');
const router = express.Router();
const Logistics = require('../models/Logistics');
const Medicine = require('../models/Medicine');
const auth = require('../middlewares/auth');

// Volunteer claims a medicine for pickup
router.post('/pickup/:medicineId', auth, async (req, res) => {
  try {
    // Only allow if user is a volunteer (optionally add role check)
    const logistics = new Logistics({
      medicine: req.params.medicineId,
      volunteer: req.user.id,
      pickupDate: new Date(),
      status: 'picked'
    });
    await logistics.save();
    res.json({ message: 'Pickup assigned!', logistics });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Mark as delivered
router.post('/deliver/:medicineId', auth, async (req, res) => {
  try {
    const logistics = await Logistics.findOne({ medicine: req.params.medicineId, volunteer: req.user.id });
    if (!logistics) return res.status(404).json({ error: 'Not found' });
    logistics.status = 'delivered';
    logistics.deliveryDate = new Date();
    await logistics.save();
    res.json({ message: 'Marked as delivered!', logistics });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// List all logistics entries for this volunteer
router.get('/my', auth, async (req, res) => {
  const entries = await Logistics.find({ volunteer: req.user.id })
    .populate('medicine');
  res.json(entries);
});

module.exports = router;
