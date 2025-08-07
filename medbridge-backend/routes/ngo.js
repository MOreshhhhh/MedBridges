const express = require('express');
const router = express.Router();
const auth = require('../middlewares/auth');
const Medicine = require('../models/Medicine');

// NGO Dashboard route
router.get('/dashboard', auth, async (req, res) => {
  try {
    const user = req.user;

    // Only allow NGO role access
    if (user.role !== 'ngo') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const totalDonatedMedicines = await Medicine.countDocuments({ donor: user._id });
    const totalClaimedMedicines = await Medicine.countDocuments({ claimedBy: user._id, status: 'claimed' });
    const pendingRequests = await Medicine.countDocuments({ status: 'pending', donor: user._id });

    const medicines = await Medicine.find({
      $or: [{ donor: user._id }, { claimedBy: user._id }]
    }).sort({ uploadedAt: -1 });

    res.json({
      totalDonatedMedicines,
      totalClaimedMedicines,
      pendingRequests,
      medicines,
    });
  } catch (err) {
    console.error('Error fetching NGO dashboard:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
