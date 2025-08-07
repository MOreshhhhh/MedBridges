const mongoose = require('mongoose');


const medicineSchema = new mongoose.Schema({
  verified: { type: Boolean, default: false },
  isBlocked: { type: Boolean, default: false },
  name: { type: String, required: true },
  expiryDate: { type: Date, required: true },
  quantity: { type: Number, required: true },
  photoUrl: String,
  donor: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: {
    type: String,
    enum: ['pending', 'approved', 'claimed', 'picked_up', 'delivered', 'rejected'],
    default: 'pending'
  },
  claimedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

module.exports = mongoose.model('Medicine', medicineSchema);
