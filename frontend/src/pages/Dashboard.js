import React from 'react';
import { 
  Container, 
  Typography, 
  Box, 
  Paper, 
  Grid,
  Card,
  CardContent,
  CardHeader,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Button
} from '@mui/material';
import {
  Security as SecurityIcon,
  BugReport as BugReportIcon,
  Speed as SpeedIcon,
  Assessment as AssessmentIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const Dashboard = () => {
  const { currentUser } = useAuth();
  const navigate = useNavigate();

  // Mock data for dashboard
  const stats = {
    totalScans: 24,
    activeScans: 2,
    totalVulnerabilities: 156,
    criticalVulnerabilities: 12,
    highVulnerabilities: 38,
    mediumVulnerabilities: 67,
    lowVulnerabilities: 39
  };

  const recentScans = [
    { id: 1, target: 'https://example.com', date: '2025-04-15', status: 'Completed', findings: 8 },
    { id: 2, target: 'https://test-api.example.org', date: '2025-04-14', status: 'Completed', findings: 12 },
    { id: 3, target: 'https://dev.example.net', date: '2025-04-13', status: 'In Progress', findings: 5 }
  ];

  return (
    <Container maxWidth="lg">
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Welcome, {currentUser?.name || 'User'}
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Here's an overview of your security testing activities
        </Typography>
      </Box>

      <Grid container spacing={3}>
        {/* Stats Cards */}
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <SecurityIcon color="primary" sx={{ fontSize: 48, mb: 1 }} />
              <Typography variant="h4">{stats.totalScans}</Typography>
              <Typography variant="body2" color="text.secondary">Total Scans</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <SpeedIcon color="primary" sx={{ fontSize: 48, mb: 1 }} />
              <Typography variant="h4">{stats.activeScans}</Typography>
              <Typography variant="body2" color="text.secondary">Active Scans</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <BugReportIcon color="error" sx={{ fontSize: 48, mb: 1 }} />
              <Typography variant="h4">{stats.totalVulnerabilities}</Typography>
              <Typography variant="body2" color="text.secondary">Total Vulnerabilities</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <BugReportIcon color="error" sx={{ fontSize: 48, mb: 1 }} />
              <Typography variant="h4">{stats.criticalVulnerabilities}</Typography>
              <Typography variant="body2" color="text.secondary">Critical Vulnerabilities</Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Scans */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, height: '100%' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">Recent Scans</Typography>
              <Button 
                variant="outlined" 
                size="small"
                onClick={() => navigate('/scan/results')}
              >
                View All
              </Button>
            </Box>
            <Divider sx={{ mb: 2 }} />
            <List>
              {recentScans.map((scan) => (
                <ListItem 
                  key={scan.id} 
                  button 
                  onClick={() => navigate(`/scan/results/${scan.id}`)}
                  sx={{ borderRadius: 1, mb: 1, '&:hover': { bgcolor: 'action.hover' } }}
                >
                  <ListItemIcon>
                    <AssessmentIcon color={scan.status === 'Completed' ? 'success' : 'info'} />
                  </ListItemIcon>
                  <ListItemText 
                    primary={scan.target} 
                    secondary={`${scan.date} • ${scan.status} • ${scan.findings} findings`} 
                  />
                </ListItem>
              ))}
            </List>
            <Box sx={{ mt: 2, textAlign: 'center' }}>
              <Button 
                variant="contained" 
                color="primary"
                onClick={() => navigate('/scan/new')}
                fullWidth
              >
                Start New Scan
              </Button>
            </Box>
          </Paper>
        </Grid>

        {/* Vulnerability Summary */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, height: '100%' }}>
            <Typography variant="h6" sx={{ mb: 2 }}>Vulnerability Summary</Typography>
            <Divider sx={{ mb: 2 }} />
            <Box sx={{ mb: 3 }}>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Card sx={{ bgcolor: '#ffebee', p: 1 }}>
                    <CardContent sx={{ textAlign: 'center', py: 1 }}>
                      <Typography variant="h5" color="error.dark">{stats.criticalVulnerabilities}</Typography>
                      <Typography variant="body2">Critical</Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6}>
                  <Card sx={{ bgcolor: '#fff8e1', p: 1 }}>
                    <CardContent sx={{ textAlign: 'center', py: 1 }}>
                      <Typography variant="h5" color="warning.dark">{stats.highVulnerabilities}</Typography>
                      <Typography variant="body2">High</Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6}>
                  <Card sx={{ bgcolor: '#e3f2fd', p: 1 }}>
                    <CardContent sx={{ textAlign: 'center', py: 1 }}>
                      <Typography variant="h5" color="info.dark">{stats.mediumVulnerabilities}</Typography>
                      <Typography variant="body2">Medium</Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6}>
                  <Card sx={{ bgcolor: '#e8f5e9', p: 1 }}>
                    <CardContent sx={{ textAlign: 'center', py: 1 }}>
                      <Typography variant="h5" color="success.dark">{stats.lowVulnerabilities}</Typography>
                      <Typography variant="body2">Low</Typography>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Button 
                variant="outlined" 
                color="primary"
                onClick={() => navigate('/reports')}
                fullWidth
              >
                Generate Report
              </Button>
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Container>
  );
};

export default Dashboard;
