// Run this in a Node.js environment (e.g., node hash-password.js)
const bcrypt = require('bcryptjs');

const password = 'admin123';  // Change this to your desired admin password
bcrypt.hash(password, 10, (err, hash) => {
  if (err) throw err;
  console.log('Hashed password:', hash);
});
