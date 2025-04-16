const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');

// Mock user database for demo purposes
const users = [
  {
    id: '1',
    name: 'Admin User',
    email: 'admin@example.com',
    password: '$2a$10$yCfBzM71mO5q5aOcTrAcXuCkTGK2xJ2zNDwXxLQbRGGt.F.aCdmPK', // "password123"
    role: 'admin',
    createdAt: new Date('2025-01-01')
  }
];

// @route   POST api/auth/register
// @desc    Register a user
// @access  Public
router.post(
  '/register',
  [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      // Check if user exists
      const userExists = users.find(user => user.email === email);
      if (userExists) {
        return res.status(400).json({ errors: [{ msg: 'User already exists' }] });
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
        role: 'user',
        createdAt: new Date()
      };

      // Add to mock database
      users.push(newUser);

      // Create JWT
      const payload = {
        user: {
          id: newUser.id,
          role: newUser.role
        }
      };

      jwt.sign(
        payload,
        process.env.JWT_SECRET || 'securscan_jwt_secret_key',
        { expiresIn: '1d' },
        (err, token) => {
          if (err) throw err;
          res.json({
            token,
            user: {
              id: newUser.id,
              name: newUser.name,
              email: newUser.email,
              role: newUser.role
            }
          });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

// @route   POST api/auth/login
// @desc    Authenticate user & get token
// @access  Public
router.post(
  '/login',
  [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      // Check if user exists
      const user = users.find(user => user.email === email);
      if (!user) {
        return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
      }

      // Check password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
      }

      // Create JWT
      const payload = {
        user: {
          id: user.id,
          role: user.role
        }
      };

      jwt.sign(
        payload,
        process.env.JWT_SECRET || 'securscan_jwt_secret_key',
        { expiresIn: '1d' },
        (err, token) => {
          if (err) throw err;
          res.json({
            token,
            user: {
              id: user.id,
              name: user.name,
              email: user.email,
              role: user.role
            }
          });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

// @route   GET api/auth/me
// @desc    Get current user
// @access  Private
router.get('/me', (req, res) => {
  // For demo purposes, we'll just return a mock user
  // In a real app, this would verify the JWT token and return the authenticated user
  res.json({
    id: '1',
    name: 'Admin User',
    email: 'admin@example.com',
    role: 'admin'
  });
});

module.exports = router;
