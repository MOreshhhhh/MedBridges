const mongoose = require('mongoose');

const logisticsSchema = new mongoose.Schema({
  medicine: { type: mongoose.Schema.Types.ObjectId, ref: 'Medicine', required: true },
  volunteer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  pickupDate: Date,
  deliveryDate: Date,
  status: { type: String, enum: ['pending', 'picked', 'delivered'], default: 'pending' },
}, { timestamps: true });

module.exports = mongoose.model('Logistics', logisticsSchema);
