const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');

// Mock users database for demo purposes
const users = [
  {
    id: '1',
    name: 'Admin User',
    email: 'admin@securscan.com',
    role: 'admin',
    createdAt: '2025-01-15',
    lastLogin: '2025-04-15'
  },
  {
    id: '2',
    name: 'Test User',
    email: 'user@securscan.com',
    role: 'user',
    createdAt: '2025-02-20',
    lastLogin: '2025-04-14'
  },
  {
    id: '3',
    name: 'Security Analyst',
    email: 'analyst@securscan.com',
    role: 'analyst',
    createdAt: '2025-03-10',
    lastLogin: '2025-04-13'
  }
];

// Middleware to check if user is authenticated and is an admin
const adminAuth = (req, res, next) => {
  // In a real app, this would verify the JWT token and check the role
  // For demo purposes, we'll just pass through
  next();
};

// Get all users (admin only)
router.get('/', adminAuth, (req, res) => {
  try {
    // Return all users (without passwords)
    res.json(users);
  } catch (error) {
    req.logger.error('Get users error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get a specific user by ID
router.get('/:id', adminAuth, (req, res) => {
  try {
    const { id } = req.params;
    
    // Find user
    const user = users.find(u => u.id === id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Return user (without password)
    res.json(user);
  } catch (error) {
    req.logger.error('Get user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create a new user (admin only)
router.post('/', adminAuth, (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    
    // Validate required fields
    if (!name || !email || !password || !role) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Check if user already exists
    if (users.some(u => u.email === email)) {
      return res.status(400).json({ message: 'User already exists' });
    }
    
    // Create new user
    const newUser = {
      id: uuidv4(),
      name,
      email,
      role,
      createdAt: new Date().toISOString().split('T')[0],
      lastLogin: null
    };
    
    // In a real app, this would hash the password and save to database
    // For demo purposes, we'll just add to our mock database
    users.push(newUser);
    
    // Return new user (without password)
    res.status(201).json(newUser);
  } catch (error) {
    req.logger.error('Create user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update a user
router.put('/:id', adminAuth, (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, role } = req.body;
    
    // Find user
    const userIndex = users.findIndex(u => u.id === id);
    
    if (userIndex === -1) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Update user
    users[userIndex] = {
      ...users[userIndex],
      name: name || users[userIndex].name,
      email: email || users[userIndex].email,
      role: role || users[userIndex].role
    };
    
    // Return updated user
    res.json(users[userIndex]);
  } catch (error) {
    req.logger.error('Update user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete a user
router.delete('/:id', adminAuth, (req, res) => {
  try {
    const { id } = req.params;
    
    // Find user
    const userIndex = users.findIndex(u => u.id === id);
    
    if (userIndex === -1) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Remove user
    users.splice(userIndex, 1);
    
    res.json({ message: 'User deleted' });
  } catch (error) {
    req.logger.error('Delete user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Change user password (admin or self)
router.put('/:id/password', adminAuth, (req, res) => {
  try {
    const { id } = req.params;
    const { currentPassword, newPassword } = req.body;
    
    // Find user
    const userIndex = users.findIndex(u => u.id === id);
    
    if (userIndex === -1) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // In a real app, this would verify the current password and hash the new one
    // For demo purposes, we'll just return success
    
    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    req.logger.error('Change password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
