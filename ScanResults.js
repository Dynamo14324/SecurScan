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
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  TextField,
  InputAdornment,
  CircularProgress,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions
} from '@mui/material';
import { useNavigate } from 'react-router-dom';

// Icons
import SearchIcon from '@mui/icons-material/Search';
import FilterListIcon from '@mui/icons-material/FilterList';
import VisibilityIcon from '@mui/icons-material/Visibility';
import GetAppIcon from '@mui/icons-material/GetApp';
import DeleteIcon from '@mui/icons-material/Delete';
import RefreshIcon from '@mui/icons-material/Refresh';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import InfoIcon from '@mui/icons-material/Info';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

// Severity level colors
const severityColors = {
  'Critical': 'error',
  'High': 'error',
  'Medium': 'warning',
  'Low': 'info',
  'Info': 'default'
};

// Severity level icons
const severityIcons = {
  'Critical': <ErrorIcon color="error" />,
  'High': <ErrorIcon color="error" />,
  'Medium': <WarningIcon color="warning" />,
  'Low': <InfoIcon color="info" />,
  'Info': <InfoIcon color="disabled" />
};

// Mock data for scan results
const mockScanResults = [
  {
    id: 'scan-123',
    target: 'https://example.com',
    date: '2025-04-15',
    status: 'Completed',
    vulnerabilities: {
      'Critical': 3,
      'High': 5,
      'Medium': 8,
      'Low': 4,
      'Info': 2
    },
    duration: '00:45:12'
  },
  {
    id: 'scan-124',
    target: 'https://test-app.com',
    date: '2025-04-14',
    status: 'Completed',
    vulnerabilities: {
      'Critical': 0,
      'High': 2,
      'Medium': 6,
      'Low': 8,
      'Info': 5
    },
    duration: '00:32:45'
  },
  {
    id: 'scan-125',
    target: 'https://dev.internal.org',
    date: '2025-04-14',
    status: 'In Progress',
    vulnerabilities: {
      'Critical': 1,
      'High': 3,
      'Medium': 2,
      'Low': 0,
      'Info': 1
    },
    duration: '00:28:10'
  },
  {
    id: 'scan-126',
    target: 'https://api.example.org',
    date: '2025-04-13',
    status: 'Completed',
    vulnerabilities: {
      'Critical': 0,
      'High': 0,
      'Medium': 3,
      'Low': 5,
      'Info': 7
    },
    duration: '00:15:33'
  },
  {
    id: 'scan-127',
    target: 'https://legacy.example.com',
    date: '2025-04-12',
    status: 'Completed',
    vulnerabilities: {
      'Critical': 5,
      'High': 7,
      'Medium': 12,
      'Low': 8,
      'Info': 3
    },
    duration: '01:05:22'
  }
];

const ScanResults = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [scanResults, setScanResults] = useState([]);
  const [tabValue, setTabValue] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [scanToDelete, setScanToDelete] = useState(null);

  useEffect(() => {
    // Simulate API call to fetch scan results
    const fetchScanResults = async () => {
      // In a real app, this would be an API call
      setTimeout(() => {
        setScanResults(mockScanResults);
        setLoading(false);
      }, 1000);
    };

    fetchScanResults();
  }, []);

  const handleTabChange = (event, newValue) => {
    setTabValue(newValue);
  };

  const handleSearchChange = (event) => {
    setSearchTerm(event.target.value);
  };

  const handleViewScan = (scanId) => {
    navigate(`/scan/results/${scanId}`);
  };

  const handleDeleteClick = (scan) => {
    setScanToDelete(scan);
    setDeleteDialogOpen(true);
  };

  const handleDeleteConfirm = () => {
    // In a real app, this would be an API call to delete the scan
    setScanResults(scanResults.filter(scan => scan.id !== scanToDelete.id));
    setDeleteDialogOpen(false);
    setScanToDelete(null);
  };

  const handleDeleteCancel = () => {
    setDeleteDialogOpen(false);
    setScanToDelete(null);
  };

  const handleDownloadReport = (scanId) => {
    // In a real app, this would trigger a download of the scan report
    console.log(`Downloading report for scan ${scanId}`);
  };

  // Filter scan results based on search term and tab value
  const filteredScanResults = scanResults.filter(scan => {
    const matchesSearch = scan.target.toLowerCase().includes(searchTerm.toLowerCase()) || 
                         scan.id.toLowerCase().includes(searchTerm.toLowerCase());
    
    if (tabValue === 0) {
      // All scans
      return matchesSearch;
    } else if (tabValue === 1) {
      // Completed scans
      return matchesSearch && scan.status === 'Completed';
    } else if (tabValue === 2) {
      // In Progress scans
      return matchesSearch && scan.status === 'In Progress';
    } else if (tabValue === 3) {
      // With Critical Vulnerabilities
      return matchesSearch && (scan.vulnerabilities.Critical > 0);
    }
    
    return matchesSearch;
  });

  // Calculate total vulnerabilities for a scan
  const getTotalVulnerabilities = (vulnerabilities) => {
    return Object.values(vulnerabilities).reduce((sum, count) => sum + count, 0);
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Scan Results
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

      <Paper sx={{ mb: 3 }}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={tabValue} onChange={handleTabChange} aria-label="scan results tabs">
            <Tab label="All Scans" />
            <Tab label="Completed" />
            <Tab label="In Progress" />
            <Tab label="Critical Vulnerabilities" />
          </Tabs>
        </Box>
        <Box sx={{ p: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <TextField
            placeholder="Search by target or scan ID"
            variant="outlined"
            size="small"
            value={searchTerm}
            onChange={handleSearchChange}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
            }}
            sx={{ width: '300px' }}
          />
          <Box>
            <Button 
              startIcon={<FilterListIcon />} 
              variant="outlined" 
              sx={{ mr: 1 }}
            >
              Filter
            </Button>
            <Button 
              startIcon={<RefreshIcon />} 
              variant="outlined"
              onClick={() => {
                setLoading(true);
                setTimeout(() => {
                  setScanResults(mockScanResults);
                  setLoading(false);
                }, 500);
              }}
            >
              Refresh
            </Button>
          </Box>
        </Box>
      </Paper>

      <TableContainer component={Paper}>
        <Table sx={{ minWidth: 650 }} aria-label="scan results table">
          <TableHead>
            <TableRow>
              <TableCell>Target</TableCell>
              <TableCell>Date</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Vulnerabilities</TableCell>
              <TableCell>Duration</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredScanResults.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Typography variant="body1" sx={{ py: 3 }}>
                    No scan results found.
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              filteredScanResults.map((scan) => (
                <TableRow
                  key={scan.id}
                  sx={{ 
                    '&:hover': { 
                      backgroundColor: 'rgba(46, 125, 50, 0.04)' 
                    },
                    cursor: 'pointer'
                  }}
                  onClick={() => handleViewScan(scan.id)}
                >
                  <TableCell component="th" scope="row">
                    <Typography variant="body2" fontWeight="medium">
                      {scan.target}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {scan.id}
                    </Typography>
                  </TableCell>
                  <TableCell>{scan.date}</TableCell>
                  <TableCell>
                    <Chip 
                      label={scan.status} 
                      color={scan.status === 'Completed' ? 'success' : 'primary'} 
                      size="small"
                      variant={scan.status === 'In Progress' ? 'outlined' : 'filled'}
                    />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {scan.vulnerabilities.Critical > 0 && (
                        <Tooltip title={`${scan.vulnerabilities.Critical} Critical`}>
                          <Chip 
                            icon={severityIcons.Critical} 
                            label={scan.vulnerabilities.Critical} 
                            color="error" 
                            size="small" 
                          />
                        </Tooltip>
                      )}
                      {scan.vulnerabilities.High > 0 && (
                        <Tooltip title={`${scan.vulnerabilities.High} High`}>
                          <Chip 
                            icon={severityIcons.High} 
                            label={scan.vulnerabilities.High} 
                            color="error" 
                            size="small" 
                            variant="outlined"
                          />
                        </Tooltip>
                      )}
                      {scan.vulnerabilities.Medium > 0 && (
                        <Tooltip title={`${scan.vulnerabilities.Medium} Medium`}>
                          <Chip 
                            icon={severityIcons.Medium} 
                            label={scan.vulnerabilities.Medium} 
                            color="warning" 
                            size="small" 
                            variant="outlined"
                          />
                        </Tooltip>
                      )}
                      <Tooltip title="Total vulnerabilities">
                        <Typography variant="body2" color="text.secondary">
                          {getTotalVulnerabilities(scan.vulnerabilities)} total
                        </Typography>
                      </Tooltip>
                    </Box>
                  </TableCell>
                  <TableCell>{scan.duration}</TableCell>
                  <TableCell align="right">
                    <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
                      <Tooltip title="View Details">
                        <IconButton 
                          onClick={(e) => {
                            e.stopPropagation();
                            handleViewScan(scan.id);
                          }}
                        >
                          <VisibilityIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Download Report">
                        <IconButton 
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDownloadReport(scan.id);
                          }}
                        >
                          <GetAppIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete Scan">
                        <IconButton 
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDeleteClick(scan);
                          }}
                        >
                          <DeleteIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteDialogOpen}
        onClose={handleDeleteCancel}
        aria-labelledby="delete-dialog-title"
        aria-describedby="delete-dialog-description"
      >
        <DialogTitle id="delete-dialog-title">
          Delete Scan
        </DialogTitle>
        <DialogContent>
          <Typography variant="body1">
            Are you sure you want to delete the scan for {scanToDelete?.target}?
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            This action cannot be undone. All scan data and reports will be permanently deleted.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDeleteCancel}>Cancel</Button>
          <Button onClick={handleDeleteConfirm} color="error" variant="contained">
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ScanResults;
