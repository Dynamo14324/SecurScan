import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

// Create axios instance with base URL
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Add request interceptor to include auth token
api.interceptors.request.use(
  (config) => {
    const user = JSON.parse(localStorage.getItem('securscan_user'));
    if (user && user.token) {
      config.headers.Authorization = `Bearer ${user.token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Auth API calls
export const authAPI = {
  login: (email, password) => api.post('/auth/login', { email, password }),
  register: (name, email, password) => api.post('/auth/register', { name, email, password }),
  getCurrentUser: () => api.get('/auth/me')
};

// Scans API calls
export const scansAPI = {
  getAllScans: () => api.get('/scans'),
  getScanById: (id) => api.get(`/scans/${id}`),
  createScan: (scanData) => api.post('/scans', scanData),
  updateScan: (id, scanData) => api.put(`/scans/${id}`, scanData),
  deleteScan: (id) => api.delete(`/scans/${id}`)
};

// Vulnerabilities API calls
export const vulnerabilitiesAPI = {
  getAllVulnerabilities: () => api.get('/vulnerabilities'),
  getVulnerabilityById: (id) => api.get(`/vulnerabilities/${id}`),
  getVulnerabilitiesByScan: (scanId) => api.get(`/vulnerabilities/scan/${scanId}`),
  updateVulnerability: (id, data) => api.put(`/vulnerabilities/${id}`, data)
};

// Reports API calls
export const reportsAPI = {
  generateReport: (scanId, format) => api.post('/reports/generate', { scanId, format }),
  getReportById: (id) => api.get(`/reports/${id}`),
  getAllReports: () => api.get('/reports')
};

// Users API calls
export const usersAPI = {
  getAllUsers: () => api.get('/users'),
  getUserById: (id) => api.get(`/users/${id}`),
  createUser: (userData) => api.post('/users', userData),
  updateUser: (id, userData) => api.put(`/users/${id}`, userData),
  deleteUser: (id) => api.delete(`/users/${id}`)
};

// Projects API calls
export const projectsAPI = {
  getAllProjects: () => api.get('/projects'),
  getProjectById: (id) => api.get(`/projects/${id}`),
  createProject: (projectData) => api.post('/projects', projectData),
  updateProject: (id, projectData) => api.put(`/projects/${id}`, projectData),
  deleteProject: (id) => api.delete(`/projects/${id}`)
};

export default {
  auth: authAPI,
  scans: scansAPI,
  vulnerabilities: vulnerabilitiesAPI,
  reports: reportsAPI,
  users: usersAPI,
  projects: projectsAPI
};
