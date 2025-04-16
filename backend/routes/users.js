const express = require('express');
const router = express.Router();

// Mock users data for demo purposes
const users = [
  {
    id: '1',
    name: 'Admin User',
    email: 'admin@example.com',
    role: 'admin',
    createdAt: '2025-01-01'
  },
  {
    id: '2',
    name: 'Test User',
    email: 'user@example.com',
    role: 'user',
    createdAt: '2025-03-15'
  }
];

// @route   GET api/users
// @desc    Get all users
// @access  Private/Admin
router.get('/', (req, res) => {
  res.json(users);
});

// @route   GET api/users/:id
// @desc    Get user by ID
// @access  Private/Admin
router.get('/:id', (req, res) => {
  const user = users.find(user => user.id === req.params.id);
  
  if (!user) {
    return res.status(404).json({ msg: 'User not found' });
  }
  
  res.json(user);
});

// @route   POST api/users
// @desc    Create a new user
// @access  Private/Admin
router.post('/', (req, res) => {
  const { name, email, role } = req.body;
  
  if (!name || !email) {
    return res.status(400).json({ msg: 'Name and email are required' });
  }
  
  // Check if user exists
  const userExists = users.find(user => user.email === email);
  if (userExists) {
    return res.status(400).json({ msg: 'User already exists' });
  }
  
  const newUser = {
    id: (users.length + 1).toString(),
    name,
    email,
    role: role || 'user',
    createdAt: new Date().toISOString().split('T')[0]
  };
  
  users.push(newUser);
  
  res.status(201).json(newUser);
});

// @route   PUT api/users/:id
// @desc    Update user
// @access  Private/Admin
router.put('/:id', (req, res) => {
  const user = users.find(user => user.id === req.params.id);
  
  if (!user) {
    return res.status(404).json({ msg: 'User not found' });
  }
  
  const { name, email, role } = req.body;
  
  if (name) user.name = name;
  if (email) user.email = email;
  if (role) user.role = role;
  
  res.json(user);
});

// @route   DELETE api/users/:id
// @desc    Delete user
// @access  Private/Admin
router.delete('/:id', (req, res) => {
  const userIndex = users.findIndex(user => user.id === req.params.id);
  
  if (userIndex === -1) {
    return res.status(404).json({ msg: 'User not found' });
  }
  
  users.splice(userIndex, 1);
  
  res.json({ msg: 'User removed' });
});

module.exports = router;
