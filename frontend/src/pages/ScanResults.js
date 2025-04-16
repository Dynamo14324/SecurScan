import React, { useState } from 'react';
import { 
  Container, 
  Typography, 
  Box, 
  Paper, 
  Grid,
  Card,
  CardContent,
  Divider,
  Chip,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  TextField,
  InputAdornment
} from '@mui/material';
import {
  Search as SearchIcon,
  FilterList as FilterListIcon,
  BugReport as BugReportIcon,
  Security as SecurityIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

const ScanResults = () => {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState('');

  // Mock data for scan results
  const scanResults = [
    {
      id: 1,
      name: 'Main Website Scan',
      target: 'https://example.com',
      date: '2025-04-15',
      status: 'Completed',
      duration: '45 minutes',
      vulnerabilities: {
        critical: 2,
        high: 3,
        medium: 5,
        low: 8
      }
    },
    {
      id: 2,
      name: 'API Security Test',
      target: 'https://api.example.com',
      date: '2025-04-14',
      status: 'Completed',
      duration: '32 minutes',
      vulnerabilities: {
        critical: 1,
        high: 4,
        medium: 7,
        low: 3
      }
    },
    {
      id: 3,
      name: 'Development Server Scan',
      target: 'https://dev.example.com',
      date: '2025-04-13',
      status: 'In Progress',
      duration: '15 minutes',
      vulnerabilities: {
        critical: 0,
        high: 2,
        medium: 3,
        low: 0
      }
    },
    {
      id: 4,
      name: 'Admin Portal Test',
      target: 'https://admin.example.com',
      date: '2025-04-12',
      status: 'Completed',
      duration: '38 minutes',
      vulnerabilities: {
        critical: 3,
        high: 5,
        medium: 8,
        low: 12
      }
    },
    {
      id: 5,
      name: 'E-commerce Site Scan',
      target: 'https://shop.example.com',
      date: '2025-04-10',
      status: 'Completed',
      duration: '52 minutes',
      vulnerabilities: {
        critical: 0,
        high: 2,
        medium: 6,
        low: 9
      }
    }
  ];

  const filteredResults = scanResults.filter(scan => 
    scan.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    scan.target.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const getSeverityIcon = (severity, count) => {
    if (count === 0) return null;
    
    switch (severity) {
      case 'critical':
        return <ErrorIcon color="error" />;
      case 'high':
        return <WarningIcon color="warning" />;
      case 'medium':
        return <InfoIcon color="info" />;
      case 'low':
        return <CheckCircleIcon color="success" />;
      default:
        return null;
    }
  };

  const getStatusChip = (status) => {
    switch (status) {
      case 'Completed':
        return <Chip label="Completed" color="success" size="small" />;
      case 'In Progress':
        return <Chip label="In Progress" color="primary" size="small" />;
      case 'Failed':
        return <Chip label="Failed" color="error" size="small" />;
      default:
        return <Chip label={status} size="small" />;
    }
  };

  const getTotalVulnerabilities = (vulnerabilities) => {
    return vulnerabilities.critical + vulnerabilities.high + vulnerabilities.medium + vulnerabilities.low;
  };

  return (
    <Container maxWidth="lg">
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Scan Results
        </Typography>
        <Typography variant="body1" color="text.secondary">
          View and analyze your security scan results
        </Typography>
      </Box>

      <Paper sx={{ p: 2, mb: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <TextField
            placeholder="Search scans..."
            variant="outlined"
            size="small"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
            }}
            sx={{ width: 300 }}
          />
          <Box>
            <Button 
              variant="outlined" 
              startIcon={<FilterListIcon />}
              sx={{ mr: 1 }}
            >
              Filter
            </Button>
            <Button 
              variant="contained" 
              color="primary"
              startIcon={<SecurityIcon />}
              onClick={() => navigate('/scan/new')}
            >
              New Scan
            </Button>
          </Box>
        </Box>

        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Scan Name</TableCell>
                <TableCell>Target</TableCell>
                <TableCell>Date</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Duration</TableCell>
                <TableCell>Vulnerabilities</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredResults.map((scan) => (
                <TableRow 
                  key={scan.id}
                  hover
                  onClick={() => navigate(`/scan/results/${scan.id}`)}
                  sx={{ cursor: 'pointer' }}
                >
                  <TableCell>{scan.name}</TableCell>
                  <TableCell>{scan.target}</TableCell>
                  <TableCell>{scan.date}</TableCell>
                  <TableCell>{getStatusChip(scan.status)}</TableCell>
                  <TableCell>{scan.duration}</TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      {scan.vulnerabilities.critical > 0 && (
                        <Box sx={{ display: 'flex', alignItems: 'center', mr: 1 }}>
                          <ErrorIcon color="error" fontSize="small" />
                          <Typography variant="body2" sx={{ ml: 0.5 }}>
                            {scan.vulnerabilities.critical}
                          </Typography>
                        </Box>
                      )}
                      {scan.vulnerabilities.high > 0 && (
                        <Box sx={{ display: 'flex', alignItems: 'center', mr: 1 }}>
                          <WarningIcon color="warning" fontSize="small" />
                          <Typography variant="body2" sx={{ ml: 0.5 }}>
                            {scan.vulnerabilities.high}
                          </Typography>
                        </Box>
                      )}
                      {scan.vulnerabilities.medium > 0 && (
                        <Box sx={{ display: 'flex', alignItems: 'center', mr: 1 }}>
                          <InfoIcon color="info" fontSize="small" />
                          <Typography variant="body2" sx={{ ml: 0.5 }}>
                            {scan.vulnerabilities.medium}
                          </Typography>
                        </Box>
                      )}
                      {scan.vulnerabilities.low > 0 && (
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          <CheckCircleIcon color="success" fontSize="small" />
                          <Typography variant="body2" sx={{ ml: 0.5 }}>
                            {scan.vulnerabilities.low}
                          </Typography>
                        </Box>
                      )}
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Button 
                      size="small" 
                      variant="outlined"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`/scan/results/${scan.id}`);
                      }}
                    >
                      View Details
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Scan Statistics
              </Typography>
              <Divider sx={{ mb: 2 }} />
              <Box sx={{ mb: 1 }}>
                <Typography variant="body2" color="text.secondary">
                  Total Scans
                </Typography>
                <Typography variant="h5">
                  {scanResults.length}
                </Typography>
              </Box>
              <Box sx={{ mb: 1 }}>
                <Typography variant="body2" color="text.secondary">
                  Completed Scans
                </Typography>
                <Typography variant="h5">
                  {scanResults.filter(scan => scan.status === 'Completed').length}
                </Typography>
              </Box>
              <Box>
                <Typography variant="body2" color="text.secondary">
                  In Progress
                </Typography>
                <Typography variant="h5">
                  {scanResults.filter(scan => scan.status === 'In Progress').length}
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Vulnerability Summary
              </Typography>
              <Divider sx={{ mb: 2 }} />
              <Grid container spacing={2}>
                <Grid item xs={6} sm={3}>
                  <Box sx={{ textAlign: 'center', p: 1, bgcolor: '#ffebee', borderRadius: 1 }}>
                    <ErrorIcon color="error" />
                    <Typography variant="h5">
                      {scanResults.reduce((total, scan) => total + scan.vulnerabilities.critical, 0)}
                    </Typography>
                    <Typography variant="body2">Critical</Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box sx={{ textAlign: 'center', p: 1, bgcolor: '#fff8e1', borderRadius: 1 }}>
                    <WarningIcon color="warning" />
                    <Typography variant="h5">
                      {scanResults.reduce((total, scan) => total + scan.vulnerabilities.high, 0)}
                    </Typography>
                    <Typography variant="body2">High</Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box sx={{ textAlign: 'center', p: 1, bgcolor: '#e3f2fd', borderRadius: 1 }}>
                    <InfoIcon color="info" />
                    <Typography variant="h5">
                      {scanResults.reduce((total, scan) => total + scan.vulnerabilities.medium, 0)}
                    </Typography>
                    <Typography variant="body2">Medium</Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box sx={{ textAlign: 'center', p: 1, bgcolor: '#e8f5e9', borderRadius: 1 }}>
                    <CheckCircleIcon color="success" />
                    <Typography variant="h5">
                      {scanResults.reduce((total, scan) => total + scan.vulnerabilities.low, 0)}
                    </Typography>
                    <Typography variant="body2">Low</Typography>
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Container>
  );
};

export default ScanResults;
