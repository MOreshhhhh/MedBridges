// middlewares/actionLogger.js
const ActionLog = require('../models/ActionLog');

/**
 * Logs an action taken by a user
 * @param {ObjectId} userId - ID of the user performing the action
 * @param {String} action - Action description string
 * @param {Object} details - Additional data about the action
 */
async function logAction(userId, action, details = {}) {
  try {
    await ActionLog.create({
      user: userId,
      action,
      details
    });
  } catch (err) {
    console.error('Failed to log action:', err);
  }
}

module.exports = logAction;
