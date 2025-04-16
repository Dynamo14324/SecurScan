import axios from 'axios';

// Create axios instance with base URL
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || '/api',
  headers: {
    'Content-Type': 'application/json'
  }
});

// Add request interceptor to add auth token to requests
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('securscan_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Add response interceptor to handle common errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Handle 401 Unauthorized errors
    if (error.response && error.response.status === 401) {
      // Clear local storage and redirect to login
      localStorage.removeItem('securscan_token');
      localStorage.removeItem('securscan_user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Auth API
export const authAPI = {
  login: (email, password) => api.post('/auth/login', { email, password }),
  register: (name, email, password) => api.post('/auth/register', { name, email, password }),
  getCurrentUser: () => api.get('/auth/me')
};

// Scans API
export const scansAPI = {
  getAllScans: () => api.get('/scans'),
  getScanById: (id) => api.get(`/scans/${id}`),
  startScan: (scanConfig) => api.post('/scans', scanConfig),
  deleteScan: (id) => api.delete(`/scans/${id}`),
  pauseScan: (id) => api.put(`/scans/${id}/pause`),
  resumeScan: (id) => api.put(`/scans/${id}/resume`),
  stopScan: (id) => api.put(`/scans/${id}/stop`)
};

// Vulnerabilities API
export const vulnerabilitiesAPI = {
  getVulnerabilitiesByScan: (scanId) => api.get(`/vulnerabilities/scan/${scanId}`),
  getVulnerabilityById: (id) => api.get(`/vulnerabilities/${id}`),
  verifyVulnerability: (id) => api.post(`/vulnerabilities/${id}/verify`),
  updateVulnerability: (id, updates) => api.put(`/vulnerabilities/${id}`, updates),
  getVulnerabilityStats: () => api.get('/vulnerabilities/stats/summary')
};

// Reports API
export const reportsAPI = {
  getReportByScan: (scanId) => api.get(`/reports/scan/${scanId}`),
  getReportById: (id) => api.get(`/reports/${id}`),
  generateReport: (scanId, format = 'html') => api.post(`/reports/generate/${scanId}`, { format }),
  downloadReport: (id, format) => api.get(`/reports/${id}/download/${format}`),
  getAllReports: () => api.get('/reports'),
  deleteReport: (id) => api.delete(`/reports/${id}`)
};

// Users API
export const usersAPI = {
  getAllUsers: () => api.get('/users'),
  getUserById: (id) => api.get(`/users/${id}`),
  createUser: (userData) => api.post('/users', userData),
  updateUser: (id, updates) => api.put(`/users/${id}`, updates),
  deleteUser: (id) => api.delete(`/users/${id}`),
  changePassword: (id, currentPassword, newPassword) => 
    api.put(`/users/${id}/password`, { currentPassword, newPassword })
};

// Projects API
export const projectsAPI = {
  getAllProjects: () => api.get('/projects'),
  getProjectById: (id) => api.get(`/projects/${id}`),
  createProject: (projectData) => api.post('/projects', projectData),
  updateProject: (id, updates) => api.put(`/projects/${id}`, updates),
  deleteProject: (id) => api.delete(`/projects/${id}`),
  addMember: (id, userId) => api.post(`/projects/${id}/members`, { userId }),
  removeMember: (id, userId) => api.delete(`/projects/${id}/members/${userId}`),
  addScan: (id, scanId) => api.post(`/projects/${id}/scans`, { scanId }),
  removeScan: (id, scanId) => api.delete(`/projects/${id}/scans/${scanId}`)
};

// Test Cases API
export const testCasesAPI = {
  getAllTestCases: () => api.get('/test-cases'),
  getTestCasesByCategory: (category) => api.get(`/test-cases/category/${category}`),
  getTestCaseById: (id) => api.get(`/test-cases/${id}`),
  createTestCase: (testCaseData) => api.post('/test-cases', testCaseData),
  createFromTemplate: (templateName, overrides) => 
    api.post('/test-cases/from-template', { templateName, overrides }),
  updateTestCase: (id, updates) => api.put(`/test-cases/${id}`, updates),
  deleteTestCase: (id) => api.delete(`/test-cases/${id}`),
  getTestCaseHistory: (id) => api.get(`/test-cases/${id}/history`),
  restoreVersion: (id, version) => api.post(`/test-cases/${id}/restore/${version}`),
  searchTestCases: (criteria) => api.post('/test-cases/search', criteria),
  exportTestCases: (testCases, format) => api.post('/test-cases/export', { testCases, format }),
  importTestCases: (importData) => api.post('/test-cases/import', { importData })
};

export default {
  auth: authAPI,
  scans: scansAPI,
  vulnerabilities: vulnerabilitiesAPI,
  reports: reportsAPI,
  users: usersAPI,
  projects: projectsAPI,
  testCases: testCasesAPI
};
