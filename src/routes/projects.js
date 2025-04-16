const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');

// Mock projects database for demo purposes
const projects = [
  {
    id: 'proj-001',
    name: 'E-Commerce Website',
    description: 'Security assessment of the company e-commerce platform',
    createdAt: '2025-03-15',
    updatedAt: '2025-04-15',
    owner: '1',
    members: ['1', '2', '3'],
    scans: ['scan-123', 'scan-124'],
    status: 'active'
  },
  {
    id: 'proj-002',
    name: 'Mobile Banking App',
    description: 'Security testing of the mobile banking application',
    createdAt: '2025-04-01',
    updatedAt: '2025-04-14',
    owner: '1',
    members: ['1', '3'],
    scans: ['scan-125'],
    status: 'active'
  },
  {
    id: 'proj-003',
    name: 'Internal HR Portal',
    description: 'Vulnerability assessment of the internal HR portal',
    createdAt: '2025-02-20',
    updatedAt: '2025-04-10',
    owner: '2',
    members: ['2'],
    scans: [],
    status: 'completed'
  }
];

// Middleware to check if user is authenticated
const auth = (req, res, next) => {
  // In a real app, this would verify the JWT token
  // For demo purposes, we'll just pass through
  next();
};

// Get all projects for the authenticated user
router.get('/', auth, (req, res) => {
  try {
    // In a real app, this would filter by userId from the JWT token
    // For demo purposes, return all projects
    res.json(projects);
  } catch (error) {
    req.logger.error('Get projects error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get a specific project by ID
router.get('/:id', auth, (req, res) => {
  try {
    const { id } = req.params;
    
    // Find project
    const project = projects.find(p => p.id === id);
    
    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    // In a real app, check if user is a member of the project
    // if (!project.members.includes(req.user.id)) {
    //   return res.status(403).json({ message: 'Not authorized' });
    // }
    
    res.json(project);
  } catch (error) {
    req.logger.error('Get project error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create a new project
router.post('/', auth, (req, res) => {
  try {
    const { name, description } = req.body;
    
    // Validate required fields
    if (!name) {
      return res.status(400).json({ message: 'Project name is required' });
    }
    
    // Create new project
    const newProject = {
      id: `proj-${uuidv4()}`,
      name,
      description: description || '',
      createdAt: new Date().toISOString().split('T')[0],
      updatedAt: new Date().toISOString().split('T')[0],
      owner: '1', // In a real app, this would be req.user.id
      members: ['1'], // In a real app, this would include req.user.id
      scans: [],
      status: 'active'
    };
    
    // Add to projects
    projects.push(newProject);
    
    res.status(201).json(newProject);
  } catch (error) {
    req.logger.error('Create project error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update a project
router.put('/:id', auth, (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, status } = req.body;
    
    // Find project
    const projectIndex = projects.findIndex(p => p.id === id);
    
    if (projectIndex === -1) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    // In a real app, check if user is the owner of the project
    // if (projects[projectIndex].owner !== req.user.id) {
    //   return res.status(403).json({ message: 'Not authorized' });
    // }
    
    // Update project
    projects[projectIndex] = {
      ...projects[projectIndex],
      name: name || projects[projectIndex].name,
      description: description !== undefined ? description : projects[projectIndex].description,
      status: status || projects[projectIndex].status,
      updatedAt: new Date().toISOString().split('T')[0]
    };
    
    res.json(projects[projectIndex]);
  } catch (error) {
    req.logger.error('Update project error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete a project
router.delete('/:id', auth, (req, res) => {
  try {
    const { id } = req.params;
    
    // Find project
    const projectIndex = projects.findIndex(p => p.id === id);
    
    if (projectIndex === -1) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    // In a real app, check if user is the owner of the project
    // if (projects[projectIndex].owner !== req.user.id) {
    //   return res.status(403).json({ message: 'Not authorized' });
    // }
    
    // Remove project
    projects.splice(projectIndex, 1);
    
    res.json({ message: 'Project deleted' });
  } catch (error) {
    req.logger.error('Delete project error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add a member to a project
router.post('/:id/members', auth, (req, res) => {
  try {
    const { id } = req.params;
    const { userId } = req.body;
    
    // Validate required fields
    if (!userId) {
      return res.status(400).json({ message: 'User ID is required' });
    }
    
    // Find project
    const projectIndex = projects.findIndex(p => p.id === id);
    
    if (projectIndex === -1) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    // In a real app, check if user is the owner of the project
    // if (projects[projectIndex].owner !== req.user.id) {
    //   return res.status(403).json({ message: 'Not authorized' });
    // }
    
    // Check if user is already a member
    if (projects[projectIndex].members.includes(userId)) {
      return res.status(400).json({ message: 'User is already a member of this project' });
    }
    
    // Add member
    projects[projectIndex].members.push(userId);
    projects[projectIndex].updatedAt = new Date().toISOString().split('T')[0];
    
    res.json(projects[projectIndex]);
  } catch (error) {
    req.logger.error('Add member error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Remove a member from a project
router.delete('/:id/members/:userId', auth, (req, res) => {
  try {
    const { id, userId } = req.params;
    
    // Find project
    const projectIndex = projects.findIndex(p => p.id === id);
    
    if (projectIndex === -1) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    // In a real app, check if user is the owner of the project
    // if (projects[projectIndex].owner !== req.user.id) {
    //   return res.status(403).json({ message: 'Not authorized' });
    // }
    
    // Check if user is the owner
    if (projects[projectIndex].owner === userId) {
      return res.status(400).json({ message: 'Cannot remove the project owner' });
    }
    
    // Check if user is a member
    const memberIndex = projects[projectIndex].members.indexOf(userId);
    if (memberIndex === -1) {
      return res.status(400).json({ message: 'User is not a member of this project' });
    }
    
    // Remove member
    projects[projectIndex].members.splice(memberIndex, 1);
    projects[projectIndex].updatedAt = new Date().toISOString().split('T')[0];
    
    res.json(projects[projectIndex]);
  } catch (error) {
    req.logger.error('Remove member error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add a scan to a project
router.post('/:id/scans', auth, (req, res) => {
  try {
    const { id } = req.params;
    const { scanId } = req.body;
    
    // Validate required fields
    if (!scanId) {
      return res.status(400).json({ message: 'Scan ID is required' });
    }
    
    // Find project
    const projectIndex = projects.findIndex(p => p.id === id);
    
    if (projectIndex === -1) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    // In a real app, check if user is a member of the project
    // if (!projects[projectIndex].members.includes(req.user.id)) {
    //   return res.status(403).json({ message: 'Not authorized' });
    // }
    
    // Check if scan is already in the project
    if (projects[projectIndex].scans.includes(scanId)) {
      return res.status(400).json({ message: 'Scan is already in this project' });
    }
    
    // Add scan
    projects[projectIndex].scans.push(scanId);
    projects[projectIndex].updatedAt = new Date().toISOString().split('T')[0];
    
    res.json(projects[projectIndex]);
  } catch (error) {
    req.logger.error('Add scan error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Remove a scan from a project
router.delete('/:id/scans/:scanId', auth, (req, res) => {
  try {
    const { id, scanId } = req.params;
    
    // Find project
    const projectIndex = projects.findIndex(p => p.id === id);
    
    if (projectIndex === -1) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    // In a real app, check if user is a member of the project
    // if (!projects[projectIndex].members.includes(req.user.id)) {
    //   return res.status(403).json({ message: 'Not authorized' });
    // }
    
    // Check if scan is in the project
    const scanIndex = projects[projectIndex].scans.indexOf(scanId);
    if (scanIndex === -1) {
      return res.status(400).json({ message: 'Scan is not in this project' });
    }
    
    // Remove scan
    projects[projectIndex].scans.splice(scanIndex, 1);
    projects[projectIndex].updatedAt = new Date().toISOString().split('T')[0];
    
    res.json(projects[projectIndex]);
  } catch (error) {
    req.logger.error('Remove scan error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
