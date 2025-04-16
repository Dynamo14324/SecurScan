const express = require('express');
const router = express.Router();

// Mock projects data for demo purposes
const projects = [
  {
    id: '1',
    name: 'Main Website',
    description: 'Corporate website security testing',
    target: 'https://example.com',
    createdAt: '2025-03-01',
    status: 'Active',
    scans: ['1']
  },
  {
    id: '2',
    name: 'API Services',
    description: 'Backend API security assessment',
    target: 'https://api.example.com',
    createdAt: '2025-03-15',
    status: 'Active',
    scans: ['2']
  },
  {
    id: '3',
    name: 'Development Environment',
    description: 'Testing environment security checks',
    target: 'https://dev.example.com',
    createdAt: '2025-04-01',
    status: 'Active',
    scans: ['3']
  }
];

// @route   GET api/projects
// @desc    Get all projects
// @access  Private
router.get('/', (req, res) => {
  res.json(projects);
});

// @route   GET api/projects/:id
// @desc    Get project by ID
// @access  Private
router.get('/:id', (req, res) => {
  const project = projects.find(project => project.id === req.params.id);
  
  if (!project) {
    return res.status(404).json({ msg: 'Project not found' });
  }
  
  res.json(project);
});

// @route   POST api/projects
// @desc    Create a new project
// @access  Private
router.post('/', (req, res) => {
  const { name, description, target } = req.body;
  
  if (!name || !target) {
    return res.status(400).json({ msg: 'Name and target are required' });
  }
  
  const newProject = {
    id: (projects.length + 1).toString(),
    name,
    description: description || '',
    target,
    createdAt: new Date().toISOString().split('T')[0],
    status: 'Active',
    scans: []
  };
  
  projects.push(newProject);
  
  res.status(201).json(newProject);
});

// @route   PUT api/projects/:id
// @desc    Update project
// @access  Private
router.put('/:id', (req, res) => {
  const project = projects.find(project => project.id === req.params.id);
  
  if (!project) {
    return res.status(404).json({ msg: 'Project not found' });
  }
  
  const { name, description, target, status } = req.body;
  
  if (name) project.name = name;
  if (description) project.description = description;
  if (target) project.target = target;
  if (status) project.status = status;
  
  res.json(project);
});

// @route   DELETE api/projects/:id
// @desc    Delete project
// @access  Private
router.delete('/:id', (req, res) => {
  const projectIndex = projects.findIndex(project => project.id === req.params.id);
  
  if (projectIndex === -1) {
    return res.status(404).json({ msg: 'Project not found' });
  }
  
  projects.splice(projectIndex, 1);
  
  res.json({ msg: 'Project removed' });
});

// @route   GET api/projects/:id/scans
// @desc    Get all scans for a project
// @access  Private
router.get('/:id/scans', (req, res) => {
  const project = projects.find(project => project.id === req.params.id);
  
  if (!project) {
    return res.status(404).json({ msg: 'Project not found' });
  }
  
  // Mock scans data
  const scans = [
    {
      id: '1',
      name: 'Main Website Scan',
      target: 'https://example.com',
      date: '2025-04-15',
      status: 'Completed'
    },
    {
      id: '2',
      name: 'API Security Test',
      target: 'https://api.example.com',
      date: '2025-04-14',
      status: 'Completed'
    },
    {
      id: '3',
      name: 'Development Server Scan',
      target: 'https://dev.example.com',
      date: '2025-04-13',
      status: 'In Progress'
    }
  ];
  
  const projectScans = scans.filter(scan => project.scans.includes(scan.id));
  
  res.json(projectScans);
});

// @route   POST api/projects/:id/scans
// @desc    Add a scan to a project
// @access  Private
router.post('/:id/scans', (req, res) => {
  const project = projects.find(project => project.id === req.params.id);
  
  if (!project) {
    return res.status(404).json({ msg: 'Project not found' });
  }
  
  const { scanId } = req.body;
  
  if (!scanId) {
    return res.status(400).json({ msg: 'Scan ID is required' });
  }
  
  if (project.scans.includes(scanId)) {
    return res.status(400).json({ msg: 'Scan already added to project' });
  }
  
  project.scans.push(scanId);
  
  res.json(project);
});

module.exports = router;
