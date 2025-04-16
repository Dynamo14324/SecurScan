import React, { useState } from 'react';
import { 
  Container, 
  Typography, 
  Box, 
  Paper, 
  Grid,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Divider,
  Stepper,
  Step,
  StepLabel,
  Card,
  CardContent,
  Switch,
  FormControlLabel,
  Alert
} from '@mui/material';
import { 
  Security as SecurityIcon,
  Send as SendIcon
} from '@mui/icons-material';

const ScanConfiguration = () => {
  const [activeStep, setActiveStep] = useState(0);
  const [targetUrl, setTargetUrl] = useState('');
  const [scanName, setScanName] = useState('');
  const [scanType, setScanType] = useState('full');
  const [scanOptions, setScanOptions] = useState({
    sqlInjection: true,
    xss: true,
    csrf: true,
    ssrf: true,
    xxe: true,
    commandInjection: true,
    fileInclusion: true,
    insecureDeserialization: true,
    authBypass: true,
    accessControl: true
  });
  const [throttling, setThrottling] = useState(50);
  const [error, setError] = useState('');

  const steps = ['Target Information', 'Scan Options', 'Review & Start'];

  const handleNext = () => {
    if (activeStep === 0 && !validateTargetInfo()) {
      return;
    }
    setActiveStep((prevActiveStep) => prevActiveStep + 1);
  };

  const handleBack = () => {
    setActiveStep((prevActiveStep) => prevActiveStep - 1);
  };

  const validateTargetInfo = () => {
    if (!targetUrl) {
      setError('Target URL is required');
      return false;
    }
    
    try {
      new URL(targetUrl);
    } catch (e) {
      setError('Please enter a valid URL (including http:// or https://)');
      return false;
    }
    
    if (!scanName) {
      setError('Scan name is required');
      return false;
    }
    
    setError('');
    return true;
  };

  const handleScanTypeChange = (event) => {
    const type = event.target.value;
    setScanType(type);
    
    // Update scan options based on scan type
    if (type === 'full') {
      setScanOptions({
        sqlInjection: true,
        xss: true,
        csrf: true,
        ssrf: true,
        xxe: true,
        commandInjection: true,
        fileInclusion: true,
        insecureDeserialization: true,
        authBypass: true,
        accessControl: true
      });
    } else if (type === 'quick') {
      setScanOptions({
        sqlInjection: true,
        xss: true,
        csrf: true,
        ssrf: false,
        xxe: false,
        commandInjection: true,
        fileInclusion: false,
        insecureDeserialization: false,
        authBypass: false,
        accessControl: false
      });
    } else if (type === 'custom') {
      // Keep current options
    }
  };

  const handleOptionChange = (option) => {
    setScanOptions({
      ...scanOptions,
      [option]: !scanOptions[option]
    });
    
    // If custom options are selected, change scan type to custom
    setScanType('custom');
  };

  const handleStartScan = () => {
    // In a real app, this would make an API call to start the scan
    // For demo purposes, we'll just simulate a successful scan start
    alert('Scan started successfully! This is a demo, so no actual scan will be performed.');
    
    // Reset form
    setActiveStep(0);
    setTargetUrl('');
    setScanName('');
    setScanType('full');
    setScanOptions({
      sqlInjection: true,
      xss: true,
      csrf: true,
      ssrf: true,
      xxe: true,
      commandInjection: true,
      fileInclusion: true,
      insecureDeserialization: true,
      authBypass: true,
      accessControl: true
    });
    setThrottling(50);
  };

  const renderStepContent = (step) => {
    switch (step) {
      case 0:
        return (
          <Box sx={{ mt: 2 }}>
            {error && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {error}
              </Alert>
            )}
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Target URL"
                  variant="outlined"
                  placeholder="https://example.com"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  required
                  helperText="Enter the full URL of the target website or API"
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Scan Name"
                  variant="outlined"
                  placeholder="My Test Scan"
                  value={scanName}
                  onChange={(e) => setScanName(e.target.value)}
                  required
                  helperText="Enter a name to identify this scan"
                />
              </Grid>
              <Grid item xs={12}>
                <FormControl fullWidth>
                  <InputLabel>Scan Type</InputLabel>
                  <Select
                    value={scanType}
                    label="Scan Type"
                    onChange={handleScanTypeChange}
                  >
                    <MenuItem value="quick">Quick Scan</MenuItem>
                    <MenuItem value="full">Full Scan</MenuItem>
                    <MenuItem value="custom">Custom Scan</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
          </Box>
        );
      case 1:
        return (
          <Box sx={{ mt: 2 }}>
            <Typography variant="h6" gutterBottom>
              Vulnerability Checks
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={scanOptions.sqlInjection}
                      onChange={() => handleOptionChange('sqlInjection')}
                      color="primary"
                    />
                  }
                  label="SQL Injection"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={scanOptions.xss}
                      onChange={() => handleOptionChange('xss')}
                      color="primary"
                    />
                  }
                  label="Cross-Site Scripting (XSS)"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={scanOptions.csrf}
                      onChange={() => handleOptionChange('csrf')}
                      color="primary"
                    />
                  }
                  label="CSRF Token Validation"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={scanOptions.ssrf}
                      onChange={() => handleOptionChange('ssrf')}
                      color="primary"
                    />
                  }
                  label="Server-Side Request Forgery"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={scanOptions.xxe}
                      onChange={() => handleOptionChange('xxe')}
                      color="primary"
                    />
                  }
                  label="XML External Entity"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={scanOptions.commandInjection}
                      onChange={() => handleOptionChange('commandInjection')}
                      color="primary"
                    />
                  }
                  label="Command Injection"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={scanOptions.fileInclusion}
                      onChange={() => handleOptionChange('fileInclusion')}
                      color="primary"
                    />
                  }
                  label="File Inclusion"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={scanOptions.insecureDeserialization}
                      onChange={() => handleOptionChange('insecureDeserialization')}
                      color="primary"
                    />
                  }
                  label="Insecure Deserialization"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={scanOptions.authBypass}
                      onChange={() => handleOptionChange('authBypass')}
                      color="primary"
                    />
                  }
                  label="Authentication Bypass"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={scanOptions.accessControl}
                      onChange={() => handleOptionChange('accessControl')}
                      color="primary"
                    />
                  }
                  label="Access Control"
                />
              </Grid>
            </Grid>
            
            <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
              Scan Performance
            </Typography>
            <Box sx={{ px: 2 }}>
              <Typography variant="body2" gutterBottom>
                Throttling: {throttling}%
              </Typography>
              <Grid container spacing={2} alignItems="center">
                <Grid item>
                  <Typography variant="body2">Slower</Typography>
                </Grid>
                <Grid item xs>
                  <input
                    type="range"
                    min="10"
                    max="100"
                    value={throttling}
                    onChange={(e) => setThrottling(e.target.value)}
                    style={{ width: '100%' }}
                  />
                </Grid>
                <Grid item>
                  <Typography variant="body2">Faster</Typography>
                </Grid>
              </Grid>
              <Typography variant="caption" color="text.secondary">
                Higher values may cause more load on the target system
              </Typography>
            </Box>
          </Box>
        );
      case 2:
        return (
          <Box sx={{ mt: 2 }}>
            <Typography variant="h6" gutterBottom>
              Scan Configuration Summary
            </Typography>
            <Card variant="outlined" sx={{ mb: 3 }}>
              <CardContent>
                <Typography variant="subtitle1" gutterBottom>
                  Target Information
                </Typography>
                <Typography variant="body2" gutterBottom>
                  <strong>URL:</strong> {targetUrl}
                </Typography>
                <Typography variant="body2" gutterBottom>
                  <strong>Scan Name:</strong> {scanName}
                </Typography>
                <Typography variant="body2" gutterBottom>
                  <strong>Scan Type:</strong> {scanType.charAt(0).toUpperCase() + scanType.slice(1)} Scan
                </Typography>
                
                <Divider sx={{ my: 2 }} />
                
                <Typography variant="subtitle1" gutterBottom>
                  Enabled Vulnerability Checks
                </Typography>
                <Grid container spacing={1}>
                  {Object.entries(scanOptions).map(([key, value]) => (
                    value && (
                      <Grid item xs={12} sm={6} key={key}>
                        <Typography variant="body2">
                          • {key.replace(/([A-Z])/g, ' $1').replace(/^./, (str) => str.toUpperCase())}
                        </Typography>
                      </Grid>
                    )
                  ))}
                </Grid>
                
                <Divider sx={{ my: 2 }} />
                
                <Typography variant="subtitle1" gutterBottom>
                  Performance Settings
                </Typography>
                <Typography variant="body2">
                  <strong>Throttling:</strong> {throttling}%
                </Typography>
              </CardContent>
            </Card>
            
            <Alert severity="info" sx={{ mb: 2 }}>
              This is a demo application. No actual scanning will be performed.
            </Alert>
          </Box>
        );
      default:
        return null;
    }
  };

  return (
    <Container maxWidth="md">
      <Paper sx={{ p: 3, mt: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
          <SecurityIcon color="primary" sx={{ fontSize: 32, mr: 2 }} />
          <Typography variant="h5" component="h1">
            Configure New Security Scan
          </Typography>
        </Box>
        
        <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
          {steps.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>
        
        {renderStepContent(activeStep)}
        
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 4 }}>
          <Button
            disabled={activeStep === 0}
            onClick={handleBack}
          >
            Back
          </Button>
          <Box>
            {activeStep === steps.length - 1 ? (
              <Button
                variant="contained"
                color="primary"
                onClick={handleStartScan}
                startIcon={<SendIcon />}
              >
                Start Scan
              </Button>
            ) : (
              <Button
                variant="contained"
                color="primary"
                onClick={handleNext}
              >
                Next
              </Button>
            )}
          </Box>
        </Box>
      </Paper>
    </Container>
  );
};

export default ScanConfiguration;
