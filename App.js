import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Box } from '@mui/material';

// Layout components
import MainLayout from './components/layouts/MainLayout';

// Pages
import Dashboard from './pages/Dashboard';
import ScanConfiguration from './pages/ScanConfiguration';
import ScanResults from './pages/ScanResults';
import VulnerabilityDetails from './pages/VulnerabilityDetails';
import Reports from './pages/Reports';
import TestCases from './pages/TestCases';
import Settings from './pages/Settings';
import UserManagement from './pages/UserManagement';
import Projects from './pages/Projects';
import Login from './pages/Login';
import Register from './pages/Register';
import NotFound from './pages/NotFound';

// Auth context
import { AuthProvider, useAuth } from './contexts/AuthContext';

// Protected route component
const ProtectedRoute = ({ children }) => {
  const { isAuthenticated } = useAuth();
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  
  return children;
};

function AppRoutes() {
  return (
    <Routes>
      {/* Public routes */}
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      
      {/* Protected routes */}
      <Route path="/" element={
        <ProtectedRoute>
          <MainLayout />
        </ProtectedRoute>
      }>
        <Route index element={<Dashboard />} />
        <Route path="scan">
          <Route path="new" element={<ScanConfiguration />} />
          <Route path="results" element={<ScanResults />} />
          <Route path="results/:scanId" element={<VulnerabilityDetails />} />
        </Route>
        <Route path="reports" element={<Reports />} />
        <Route path="test-cases" element={<TestCases />} />
        <Route path="projects" element={<Projects />} />
        <Route path="settings" element={<Settings />} />
        <Route path="users" element={<UserManagement />} />
      </Route>
      
      {/* 404 route */}
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

function App() {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </Box>
  );
}

export default App;
