const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// Mock user database for demo purposes
const users = [
  {
    id: '1',
    name: 'Admin User',
    email: 'admin@securscan.com',
    password: '$2b$10$X7o4.KmgzCp3U4dLBnmJleZXRPDCCi1bO8CIW.kC9WyYULvhTPsiO', // 'admin123'
    role: 'admin'
  },
  {
    id: '2',
    name: 'Test User',
    email: 'user@securscan.com',
    password: '$2b$10$X7o4.KmgzCp3U4dLBnmJleZXRPDCCi1bO8CIW.kC9WyYULvhTPsiO', // 'user123'
    role: 'user'
  }
];

// Login route
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user by email
    const user = users.find(u => u.email === email);
    
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'securscan_secret_key',
      { expiresIn: '1d' }
    );
    
    // Return user info and token
    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      },
      token
    });
  } catch (error) {
    req.logger.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Register route
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Check if user already exists
    if (users.some(u => u.email === email)) {
      return res.status(400).json({ message: 'User already exists' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create new user
    const newUser = {
      id: (users.length + 1).toString(),
      name,
      email,
      password: hashedPassword,
      role: 'user'
    };
    
    // In a real app, this would save to database
    users.push(newUser);
    
    // Generate JWT token
    const token = jwt.sign(
      { id: newUser.id, email: newUser.email, role: newUser.role },
      process.env.JWT_SECRET || 'securscan_secret_key',
      { expiresIn: '1d' }
    );
    
    // Return user info and token
    res.status(201).json({
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role
      },
      token
    });
  } catch (error) {
    req.logger.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get current user route
router.get('/me', (req, res) => {
  try {
    // Get token from header
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'No token, authorization denied' });
    }
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'securscan_secret_key');
    
    // Find user
    const user = users.find(u => u.id === decoded.id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Return user info
    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    req.logger.error('Get current user error:', error);
    res.status(401).json({ message: 'Token is not valid' });
  }
});

module.exports = router;
