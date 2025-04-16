import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Typography, 
  Grid, 
  Paper, 
  Card, 
  CardContent, 
  CardHeader,
  Button,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  CircularProgress
} from '@mui/material';
import { useNavigate } from 'react-router-dom';

// Icons
import BugReportIcon from '@mui/icons-material/BugReport';
import SecurityIcon from '@mui/icons-material/Security';
import WarningIcon from '@mui/icons-material/Warning';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import SearchIcon from '@mui/icons-material/Search';
import AssessmentIcon from '@mui/icons-material/Assessment';

// Charts
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title } from 'chart.js';
import { Pie, Bar } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title);

const Dashboard = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [dashboardData, setDashboardData] = useState(null);

  useEffect(() => {
    // Simulate API call to fetch dashboard data
    const fetchDashboardData = async () => {
      // In a real app, this would be an API call
      setTimeout(() => {
        setDashboardData({
          totalScans: 24,
          activeScans: 2,
          vulnerabilitiesByType: {
            'SQL Injection': 12,
            'XSS': 18,
            'CSRF': 5,
            'SSRF': 3,
            'XXE': 2,
            'Command Injection': 7,
            'File Inclusion': 4,
            'Insecure Deserialization': 3,
            'Auth Bypass': 6,
            'Access Control': 9
          },
          vulnerabilitiesBySeverity: {
            'Critical': 8,
            'High': 15,
            'Medium': 22,
            'Low': 14,
            'Info': 10
          },
          recentScans: [
            { id: 'scan-123', target: 'https://example.com', date: '2025-04-15', status: 'Completed', findings: 12 },
            { id: 'scan-124', target: 'https://test-app.com', date: '2025-04-14', status: 'Completed', findings: 8 },
            { id: 'scan-125', target: 'https://dev.internal.org', date: '2025-04-14', status: 'In Progress', findings: 5 },
            { id: 'scan-126', target: 'https://api.example.org', date: '2025-04-13', status: 'In Progress', findings: 3 }
          ]
        });
        setLoading(false);
      }, 1000);
    };

    fetchDashboardData();
  }, []);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  // Prepare chart data
  const vulnerabilityTypeData = {
    labels: Object.keys(dashboardData.vulnerabilitiesByType),
    datasets: [
      {
        label: 'Vulnerabilities by Type',
        data: Object.values(dashboardData.vulnerabilitiesByType),
        backgroundColor: [
          'rgba(255, 99, 132, 0.6)',
          'rgba(54, 162, 235, 0.6)',
          'rgba(255, 206, 86, 0.6)',
          'rgba(75, 192, 192, 0.6)',
          'rgba(153, 102, 255, 0.6)',
          'rgba(255, 159, 64, 0.6)',
          'rgba(199, 199, 199, 0.6)',
          'rgba(83, 102, 255, 0.6)',
          'rgba(40, 159, 64, 0.6)',
          'rgba(210, 199, 199, 0.6)',
        ],
        borderColor: [
          'rgba(255, 99, 132, 1)',
          'rgba(54, 162, 235, 1)',
          'rgba(255, 206, 86, 1)',
          'rgba(75, 192, 192, 1)',
          'rgba(153, 102, 255, 1)',
          'rgba(255, 159, 64, 1)',
          'rgba(199, 199, 199, 1)',
          'rgba(83, 102, 255, 1)',
          'rgba(40, 159, 64, 1)',
          'rgba(210, 199, 199, 1)',
        ],
        borderWidth: 1,
      },
    ],
  };

  const severityColors = {
    'Critical': 'rgba(220, 53, 69, 0.6)',
    'High': 'rgba(253, 126, 20, 0.6)',
    'Medium': 'rgba(255, 193, 7, 0.6)',
    'Low': 'rgba(13, 110, 253, 0.6)',
    'Info': 'rgba(108, 117, 125, 0.6)'
  };

  const severityBorderColors = {
    'Critical': 'rgba(220, 53, 69, 1)',
    'High': 'rgba(253, 126, 20, 1)',
    'Medium': 'rgba(255, 193, 7, 1)',
    'Low': 'rgba(13, 110, 253, 1)',
    'Info': 'rgba(108, 117, 125, 1)'
  };

  const vulnerabilitySeverityData = {
    labels: Object.keys(dashboardData.vulnerabilitiesBySeverity),
    datasets: [
      {
        label: 'Vulnerabilities by Severity',
        data: Object.values(dashboardData.vulnerabilitiesBySeverity),
        backgroundColor: Object.keys(dashboardData.vulnerabilitiesBySeverity).map(key => severityColors[key]),
        borderColor: Object.keys(dashboardData.vulnerabilitiesBySeverity).map(key => severityBorderColors[key]),
        borderWidth: 1,
      },
    ],
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Dashboard
        </Typography>
        <Button 
          variant="contained" 
          color="primary" 
          startIcon={<SearchIcon />}
          onClick={() => navigate('/scan/new')}
        >
          New Scan
        </Button>
      </Box>

      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Paper elevation={2} sx={{ p: 2, display: 'flex', flexDirection: 'column', height: 140 }}>
            <Typography variant="h6" color="text.secondary" gutterBottom>
              Total Scans
            </Typography>
            <Typography component="p" variant="h3" sx={{ flexGrow: 1 }}>
              {dashboardData.totalScans}
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <SearchIcon color="primary" sx={{ mr: 1 }} />
              <Typography variant="body2" color="text.secondary">
                All-time scans performed
              </Typography>
            </Box>
          </Paper>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Paper elevation={2} sx={{ p: 2, display: 'flex', flexDirection: 'column', height: 140 }}>
            <Typography variant="h6" color="text.secondary" gutterBottom>
              Active Scans
            </Typography>
            <Typography component="p" variant="h3" sx={{ flexGrow: 1 }}>
              {dashboardData.activeScans}
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <CircularProgress size={20} color="primary" sx={{ mr: 1 }} />
              <Typography variant="body2" color="text.secondary">
                Currently running
              </Typography>
            </Box>
          </Paper>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Paper elevation={2} sx={{ p: 2, display: 'flex', flexDirection: 'column', height: 140 }}>
            <Typography variant="h6" color="text.secondary" gutterBottom>
              Critical Findings
            </Typography>
            <Typography component="p" variant="h3" color="error" sx={{ flexGrow: 1 }}>
              {dashboardData.vulnerabilitiesBySeverity.Critical}
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <ErrorIcon color="error" sx={{ mr: 1 }} />
              <Typography variant="body2" color="text.secondary">
                Require immediate attention
              </Typography>
            </Box>
          </Paper>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Paper elevation={2} sx={{ p: 2, display: 'flex', flexDirection: 'column', height: 140 }}>
            <Typography variant="h6" color="text.secondary" gutterBottom>
              Total Vulnerabilities
            </Typography>
            <Typography component="p" variant="h3" sx={{ flexGrow: 1 }}>
              {Object.values(dashboardData.vulnerabilitiesBySeverity).reduce((a, b) => a + b, 0)}
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <BugReportIcon color="primary" sx={{ mr: 1 }} />
              <Typography variant="body2" color="text.secondary">
                Across all scans
              </Typography>
            </Box>
          </Paper>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardHeader title="Vulnerabilities by Type" />
            <Divider />
            <CardContent>
              <Box sx={{ height: 300, position: 'relative' }}>
                <Pie data={vulnerabilityTypeData} options={{ maintainAspectRatio: false }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={6}>
          <Card>
            <CardHeader title="Vulnerabilities by Severity" />
            <Divider />
            <CardContent>
              <Box sx={{ height: 300, position: 'relative' }}>
                <Bar 
                  data={vulnerabilitySeverityData} 
                  options={{ 
                    maintainAspectRatio: false,
                    scales: {
                      y: {
                        beginAtZero: true
                      }
                    }
                  }} 
                />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Recent Scans */}
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Card>
            <CardHeader 
              title="Recent Scans" 
              action={
                <Button 
                  color="primary" 
                  onClick={() => navigate('/scan/results')}
                  endIcon={<AssessmentIcon />}
                >
                  View All
                </Button>
              }
            />
            <Divider />
            <CardContent>
              <List>
                {dashboardData.recentScans.map((scan) => (
                  <React.Fragment key={scan.id}>
                    <ListItem 
                      button 
                      onClick={() => navigate(`/scan/results/${scan.id}`)}
                      sx={{ 
                        '&:hover': { 
                          backgroundColor: 'rgba(46, 125, 50, 0.08)' 
                        }
                      }}
                    >
                      <ListItemIcon>
                        {scan.status === 'Completed' ? 
                          <CheckCircleIcon color="success" /> : 
                          <CircularProgress size={24} color="primary" />
                        }
                      </ListItemIcon>
                      <ListItemText 
                        primary={scan.target} 
                        secondary={`${scan.date} • ${scan.status} • ${scan.findings} findings`} 
                      />
                      {scan.findings > 0 && (
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          <WarningIcon color={scan.findings > 10 ? "error" : "warning"} sx={{ mr: 1 }} />
                          <Typography variant="body2" color="text.secondary">
                            {scan.findings} issues
                          </Typography>
                        </Box>
                      )}
                    </ListItem>
                    <Divider variant="inset" component="li" />
                  </React.Fragment>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;
