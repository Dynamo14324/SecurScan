import React, { useState } from 'react';
import { 
  Box, 
  Typography, 
  Paper, 
  Stepper, 
  Step, 
  StepLabel, 
  Button, 
  TextField, 
  FormControl, 
  InputLabel, 
  Select, 
  MenuItem, 
  FormControlLabel, 
  Checkbox, 
  Grid, 
  Card, 
  CardContent, 
  CardHeader, 
  Divider, 
  Alert, 
  Chip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Slider,
  Tooltip,
  CircularProgress
} from '@mui/material';
import { useNavigate } from 'react-router-dom';

// Icons
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SearchIcon from '@mui/icons-material/Search';
import SettingsIcon from '@mui/icons-material/Settings';
import SecurityIcon from '@mui/icons-material/Security';
import SpeedIcon from '@mui/icons-material/Speed';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import PauseIcon from '@mui/icons-material/Pause';
import StopIcon from '@mui/icons-material/Stop';

// Form validation
import { useFormik } from 'formik';
import * as yup from 'yup';

const steps = ['Target Configuration', 'Scan Options', 'Authentication', 'Advanced Settings', 'Review & Start'];

const validationSchemas = [
  // Step 1: Target Configuration
  yup.object({
    targetUrl: yup.string().url('Enter a valid URL').required('Target URL is required'),
    targetName: yup.string().required('Target name is required'),
    targetDescription: yup.string(),
    scanScope: yup.string().required('Scan scope is required')
  }),
  // Step 2: Scan Options
  yup.object({
    scanType: yup.string().required('Scan type is required'),
    vulnerabilityTypes: yup.array().min(1, 'Select at least one vulnerability type'),
    scanDepth: yup.number().required('Scan depth is required'),
    crawlOptions: yup.object()
  }),
  // Step 3: Authentication
  yup.object({
    authType: yup.string().required('Authentication type is required'),
    username: yup.string().when('authType', {
      is: (val) => val !== 'none',
      then: yup.string().required('Username is required')
    }),
    password: yup.string().when('authType', {
      is: (val) => val !== 'none',
      then: yup.string().required('Password is required')
    }),
    loginUrl: yup.string().when('authType', {
      is: (val) => val !== 'none',
      then: yup.string().url('Enter a valid login URL').required('Login URL is required')
    })
  }),
  // Step 4: Advanced Settings
  yup.object({
    requestsPerSecond: yup.number().min(1, 'Minimum 1 request per second').max(100, 'Maximum 100 requests per second'),
    timeout: yup.number().min(1, 'Minimum 1 second').max(300, 'Maximum 300 seconds'),
    followRedirects: yup.boolean(),
    userAgent: yup.string(),
    headers: yup.array().of(
      yup.object({
        name: yup.string().required('Header name is required'),
        value: yup.string().required('Header value is required')
      })
    ),
    cookies: yup.array().of(
      yup.object({
        name: yup.string().required('Cookie name is required'),
        value: yup.string().required('Cookie value is required')
      })
    )
  }),
  // Step 5: Review & Start
  yup.object({})
];

const ScanConfiguration = () => {
  const navigate = useNavigate();
  const [activeStep, setActiveStep] = useState(0);
  const [scanStarted, setScanStarted] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('');

  const formik = useFormik({
    initialValues: {
      // Step 1: Target Configuration
      targetUrl: '',
      targetName: '',
      targetDescription: '',
      scanScope: 'full',
      
      // Step 2: Scan Options
      scanType: 'comprehensive',
      vulnerabilityTypes: ['sql-injection', 'xss', 'csrf'],
      scanDepth: 3,
      crawlOptions: {
        followLinks: true,
        maxPages: 100,
        excludeUrls: []
      },
      
      // Step 3: Authentication
      authType: 'none',
      username: '',
      password: '',
      loginUrl: '',
      logoutDetection: true,
      
      // Step 4: Advanced Settings
      requestsPerSecond: 10,
      timeout: 30,
      followRedirects: true,
      userAgent: 'SecurScan Security Testing Platform',
      headers: [],
      cookies: [],
      proxySettings: {
        useProxy: false,
        proxyUrl: '',
        proxyUsername: '',
        proxyPassword: ''
      }
    },
    validationSchema: validationSchemas[activeStep],
    onSubmit: (values) => {
      if (activeStep === steps.length - 1) {
        startScan(values);
      } else {
        handleNext();
      }
    }
  });

  const handleNext = () => {
    if (activeStep === steps.length - 1) {
      return;
    }
    
    // Validate current step
    formik.validateForm().then(errors => {
      if (Object.keys(errors).length === 0) {
        setActiveStep((prevActiveStep) => prevActiveStep + 1);
      } else {
        // Set touched for all fields to show errors
        const touchedFields = {};
        Object.keys(errors).forEach(field => {
          touchedFields[field] = true;
        });
        formik.setTouched(touchedFields);
      }
    });
  };

  const handleBack = () => {
    setActiveStep((prevActiveStep) => prevActiveStep - 1);
  };

  const startScan = (scanConfig) => {
    setScanStarted(true);
    setScanStatus('Initializing scan...');
    
    // Simulate scan progress
    let progress = 0;
    const interval = setInterval(() => {
      progress += 5;
      setScanProgress(progress);
      
      if (progress <= 10) {
        setScanStatus('Initializing scan...');
      } else if (progress <= 30) {
        setScanStatus('Crawling target website...');
      } else if (progress <= 60) {
        setScanStatus('Detecting vulnerabilities...');
      } else if (progress <= 90) {
        setScanStatus('Analyzing results...');
      } else {
        setScanStatus('Generating report...');
      }
      
      if (progress >= 100) {
        clearInterval(interval);
        setTimeout(() => {
          // Navigate to results page
          navigate('/scan/results/new-scan-123');
        }, 1000);
      }
    }, 500);
  };

  const getStepContent = (step) => {
    switch (step) {
      case 0:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Target Configuration
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  id="targetUrl"
                  name="targetUrl"
                  label="Target URL"
                  placeholder="https://example.com"
                  value={formik.values.targetUrl}
                  onChange={formik.handleChange}
                  onBlur={formik.handleBlur}
                  error={formik.touched.targetUrl && Boolean(formik.errors.targetUrl)}
                  helperText={formik.touched.targetUrl && formik.errors.targetUrl}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  id="targetName"
                  name="targetName"
                  label="Target Name"
                  placeholder="My Web Application"
                  value={formik.values.targetName}
                  onChange={formik.handleChange}
                  onBlur={formik.handleBlur}
                  error={formik.touched.targetName && Boolean(formik.errors.targetName)}
                  helperText={formik.touched.targetName && formik.errors.targetName}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel id="scanScope-label">Scan Scope</InputLabel>
                  <Select
                    labelId="scanScope-label"
                    id="scanScope"
                    name="scanScope"
                    value={formik.values.scanScope}
                    onChange={formik.handleChange}
                    onBlur={formik.handleBlur}
                    error={formik.touched.scanScope && Boolean(formik.errors.scanScope)}
                  >
                    <MenuItem value="full">Full Scan (All Pages)</MenuItem>
                    <MenuItem value="specific-directory">Specific Directory</MenuItem>
                    <MenuItem value="single-page">Single Page</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  id="targetDescription"
                  name="targetDescription"
                  label="Target Description (Optional)"
                  multiline
                  rows={3}
                  value={formik.values.targetDescription}
                  onChange={formik.handleChange}
                  onBlur={formik.handleBlur}
                />
              </Grid>
            </Grid>
          </Box>
        );
      case 1:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Scan Options
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel id="scanType-label">Scan Type</InputLabel>
                  <Select
                    labelId="scanType-label"
                    id="scanType"
                    name="scanType"
                    value={formik.values.scanType}
                    onChange={formik.handleChange}
                    onBlur={formik.handleBlur}
                    error={formik.touched.scanType && Boolean(formik.errors.scanType)}
                  >
                    <MenuItem value="comprehensive">Comprehensive (All Vulnerabilities)</MenuItem>
                    <MenuItem value="quick">Quick Scan</MenuItem>
                    <MenuItem value="custom">Custom</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography gutterBottom>Scan Depth</Typography>
                <Slider
                  id="scanDepth"
                  name="scanDepth"
                  value={formik.values.scanDepth}
                  onChange={(e, value) => formik.setFieldValue('scanDepth', value)}
                  onBlur={formik.handleBlur}
                  valueLabelDisplay="auto"
                  step={1}
                  marks
                  min={1}
                  max={5}
                />
                <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Typography variant="caption">Surface</Typography>
                  <Typography variant="caption">Deep</Typography>
                </Box>
              </Grid>
              <Grid item xs={12}>
                <Typography gutterBottom>Vulnerability Types</Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  {[
                    { value: 'sql-injection', label: 'SQL Injection' },
                    { value: 'xss', label: 'Cross-Site Scripting (XSS)' },
                    { value: 'csrf', label: 'Cross-Site Request Forgery' },
                    { value: 'ssrf', label: 'Server-Side Request Forgery' },
                    { value: 'xxe', label: 'XML External Entity' },
                    { value: 'command-injection', label: 'Command Injection' },
                    { value: 'file-inclusion', label: 'File Inclusion' },
                    { value: 'insecure-deserialization', label: 'Insecure Deserialization' },
                    { value: 'auth-bypass', label: 'Authentication Bypass' },
                    { value: 'access-control', label: 'Access Control' }
                  ].map((type) => (
                    <Chip
                      key={type.value}
                      label={type.label}
                      onClick={() => {
                        const currentTypes = [...formik.values.vulnerabilityTypes];
                        if (currentTypes.includes(type.value)) {
                          formik.setFieldValue(
                            'vulnerabilityTypes',
                            currentTypes.filter(t => t !== type.value)
                          );
                        } else {
                          formik.setFieldValue(
                            'vulnerabilityTypes',
                            [...currentTypes, type.value]
                          );
                        }
                      }}
                      color={formik.values.vulnerabilityTypes.includes(type.value) ? "primary" : "default"}
                      sx={{ m: 0.5 }}
                    />
                  ))}
                </Box>
                {formik.touched.vulnerabilityTypes && formik.errors.vulnerabilityTypes && (
                  <Typography color="error" variant="caption">
                    {formik.errors.vulnerabilityTypes}
                  </Typography>
                )}
              </Grid>
              <Grid item xs={12}>
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography>Crawl Options</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={2}>
                      <Grid item xs={12}>
                        <FormControlLabel
                          control={
                            <Checkbox
                              checked={formik.values.crawlOptions.followLinks}
                              onChange={(e) => formik.setFieldValue('crawlOptions.followLinks', e.target.checked)}
                              name="crawlOptions.followLinks"
                            />
                          }
                          label="Follow Links"
                        />
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <TextField
                          fullWidth
                          id="crawlOptions.maxPages"
                          name="crawlOptions.maxPages"
                          label="Maximum Pages to Crawl"
                          type="number"
                          value={formik.values.crawlOptions.maxPages}
                          onChange={formik.handleChange}
                          onBlur={formik.handleBlur}
                        />
                      </Grid>
                      <Grid item xs={12}>
                        <TextField
                          fullWidth
                          id="crawlOptions.excludeUrls"
                          name="crawlOptions.excludeUrls"
                          label="Exclude URLs (one per line)"
                          multiline
                          rows={3}
                          value={formik.values.crawlOptions.excludeUrls.join('\n')}
                          onChange={(e) => formik.setFieldValue('crawlOptions.excludeUrls', e.target.value.split('\n').filter(url => url.trim() !== ''))}
                          onBlur={formik.handleBlur}
                        />
                      </Grid>
                    </Grid>
                  </AccordionDetails>
                </Accordion>
              </Grid>
            </Grid>
          </Box>
        );
      case 2:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Authentication
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <FormControl fullWidth>
                  <InputLabel id="authType-label">Authentication Type</InputLabel>
                  <Select
                    labelId="authType-label"
                    id="authType"
                    name="authType"
                    value={formik.values.authType}
                    onChange={formik.handleChange}
                    onBlur={formik.handleBlur}
                    error={formik.touched.authType && Boolean(formik.errors.authType)}
                  >
                    <MenuItem value="none">No Authentication</MenuItem>
                    <MenuItem value="form">Form Authentication</MenuItem>
                    <MenuItem value="basic">HTTP Basic Authentication</MenuItem>
                    <MenuItem value="token">API Token</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              
              {formik.values.authType !== 'none' && (
                <>
                  {formik.values.authType === 'form' && (
                    <Grid item xs={12}>
                      <TextField
                        fullWidth
                        id="loginUrl"
                        name="loginUrl"
                        label="Login URL"
                        placeholder="https://example.com/login"
                        value={formik.values.loginUrl}
                        onChange={formik.handleChange}
                        onBlur={formik.handleBlur}
                        error={formik.touched.loginUrl && Boolean(formik.errors.loginUrl)}
                        helperText={formik.touched.loginUrl && formik.errors.loginUrl}
                      />
                    </Grid>
                  )}
                  
                  <Grid item xs={12} md={6}>
                    <TextField
                      fullWidth
                      id="username"
                      name="username"
                      label={formik.values.authType === 'token' ? 'Token Name' : 'Username'}
                      value={formik.values.username}
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      error={formik.touched.username && Boolean(formik.errors.username)}
                      helperText={formik.touched.username && formik.errors.username}
                    />
                  </Grid>
                  
                  <Grid item xs={12} md={6}>
                    <TextField
                      fullWidth
                      id="password"
                      name="password"
                      label={formik.values.authType === 'token' ? 'Token Value' : 'Password'}
                      type={formik.values.authType === 'token' ? 'text' : 'password'}
                      value={formik.values.password}
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      error={formik.touched.password && Boolean(formik.errors.password)}
                      helperText={formik.touched.password && formik.errors.password}
                    />
                  </Grid>
                  
                  {formik.values.authType === 'form' && (
                    <Grid item xs={12}>
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={formik.values.logoutDetection}
                            onChange={(e) => formik.setFieldValue('logoutDetection', e.target.checked)}
                            name="logoutDetection"
                          />
                        }
                        label="Enable Logout Detection"
                      />
                    </Grid>
                  )}
                </>
              )}
            </Grid>
          </Box>
        );
      case 3:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Advanced Settings
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography gutterBottom>Requests Per Second</Typography>
                <Slider
                  id="requestsPerSecond"
                  name="requestsPerSecond"
                  value={formik.values.requestsPerSecond}
                  onChange={(e, value) => formik.setFieldValue('requestsPerSecond', value)}
                  onBlur={formik.handleBlur}
                  valueLabelDisplay="auto"
                  step={1}
                  marks={[
                    { value: 1, label: '1' },
                    { value: 25, label: '25' },
                    { value: 50, label: '50' },
                    { value: 75, label: '75' },
                    { value: 100, label: '100' }
                  ]}
                  min={1}
                  max={100}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography gutterBottom>Request Timeout (seconds)</Typography>
                <Slider
                  id="timeout"
                  name="timeout"
                  value={formik.values.timeout}
                  onChange={(e, value) => formik.setFieldValue('timeout', value)}
                  onBlur={formik.handleBlur}
                  valueLabelDisplay="auto"
                  step={5}
                  marks={[
                    { value: 5, label: '5s' },
                    { value: 60, label: '60s' },
                    { value: 120, label: '120s' },
                    { value: 180, label: '180s' },
                    { value: 300, label: '300s' }
                  ]}
                  min={5}
                  max={300}
                />
              </Grid>
              <Grid item xs={12}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={formik.values.followRedirects}
                      onChange={(e) => formik.setFieldValue('followRedirects', e.target.checked)}
                      name="followRedirects"
                    />
                  }
                  label="Follow Redirects"
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  id="userAgent"
                  name="userAgent"
                  label="User Agent"
                  value={formik.values.userAgent}
                  onChange={formik.handleChange}
                  onBlur={formik.handleBlur}
                />
              </Grid>
              
              <Grid item xs={12}>
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography>Custom Headers</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Box>
                      {formik.values.headers.map((header, index) => (
                        <Grid container spacing={2} key={index} sx={{ mb: 2 }}>
                          <Grid item xs={5}>
                            <TextField
                              fullWidth
                              label="Header Name"
                              value={header.name}
                              onChange={(e) => {
                                const newHeaders = [...formik.values.headers];
                                newHeaders[index].name = e.target.value;
                                formik.setFieldValue('headers', newHeaders);
                              }}
                            />
                          </Grid>
                          <Grid item xs={5}>
                            <TextField
                              fullWidth
                              label="Header Value"
                              value={header.value}
                              onChange={(e) => {
                                const newHeaders = [...formik.values.headers];
                                newHeaders[index].value = e.target.value;
                                formik.setFieldValue('headers', newHeaders);
                              }}
                            />
                          </Grid>
                          <Grid item xs={2}>
                            <Button
                              variant="outlined"
                              color="error"
                              onClick={() => {
                                const newHeaders = [...formik.values.headers];
                                newHeaders.splice(index, 1);
                                formik.setFieldValue('headers', newHeaders);
                              }}
                              sx={{ height: '100%' }}
                            >
                              Remove
                            </Button>
                          </Grid>
                        </Grid>
                      ))}
                      <Button
                        variant="outlined"
                        onClick={() => {
                          formik.setFieldValue('headers', [
                            ...formik.values.headers,
                            { name: '', value: '' }
                          ]);
                        }}
                      >
                        Add Header
                      </Button>
                    </Box>
                  </AccordionDetails>
                </Accordion>
              </Grid>
              
              <Grid item xs={12}>
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography>Proxy Settings</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={2}>
                      <Grid item xs={12}>
                        <FormControlLabel
                          control={
                            <Checkbox
                              checked={formik.values.proxySettings.useProxy}
                              onChange={(e) => formik.setFieldValue('proxySettings.useProxy', e.target.checked)}
                              name="proxySettings.useProxy"
                            />
                          }
                          label="Use Proxy"
                        />
                      </Grid>
                      {formik.values.proxySettings.useProxy && (
                        <>
                          <Grid item xs={12}>
                            <TextField
                              fullWidth
                              id="proxySettings.proxyUrl"
                              name="proxySettings.proxyUrl"
                              label="Proxy URL"
                              placeholder="http://proxy.example.com:8080"
                              value={formik.values.proxySettings.proxyUrl}
                              onChange={formik.handleChange}
                              onBlur={formik.handleBlur}
                            />
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <TextField
                              fullWidth
                              id="proxySettings.proxyUsername"
                              name="proxySettings.proxyUsername"
                              label="Proxy Username (Optional)"
                              value={formik.values.proxySettings.proxyUsername}
                              onChange={formik.handleChange}
                              onBlur={formik.handleBlur}
                            />
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <TextField
                              fullWidth
                              id="proxySettings.proxyPassword"
                              name="proxySettings.proxyPassword"
                              label="Proxy Password (Optional)"
                              type="password"
                              value={formik.values.proxySettings.proxyPassword}
                              onChange={formik.handleChange}
                              onBlur={formik.handleBlur}
                            />
                          </Grid>
                        </>
                      )}
                    </Grid>
                  </AccordionDetails>
                </Accordion>
              </Grid>
            </Grid>
          </Box>
        );
      case 4:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Review & Start Scan
            </Typography>
            
            <Alert severity="info" sx={{ mb: 3 }}>
              Please review your scan configuration before starting the scan.
            </Alert>
            
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardHeader title="Target Information" />
                  <Divider />
                  <CardContent>
                    <Typography variant="subtitle1">Target URL:</Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>{formik.values.targetUrl}</Typography>
                    
                    <Typography variant="subtitle1">Target Name:</Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>{formik.values.targetName}</Typography>
                    
                    <Typography variant="subtitle1">Scan Scope:</Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>
                      {formik.values.scanScope === 'full' ? 'Full Scan (All Pages)' : 
                       formik.values.scanScope === 'specific-directory' ? 'Specific Directory' : 'Single Page'}
                    </Typography>
                    
                    {formik.values.targetDescription && (
                      <>
                        <Typography variant="subtitle1">Description:</Typography>
                        <Typography variant="body2" sx={{ mb: 2 }}>{formik.values.targetDescription}</Typography>
                      </>
                    )}
                  </CardContent>
                </Card>
              </Grid>
              
              <Grid item xs={12} md={6}>
                <Card>
                  <CardHeader title="Scan Options" />
                  <Divider />
                  <CardContent>
                    <Typography variant="subtitle1">Scan Type:</Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>
                      {formik.values.scanType === 'comprehensive' ? 'Comprehensive' : 
                       formik.values.scanType === 'quick' ? 'Quick Scan' : 'Custom'}
                    </Typography>
                    
                    <Typography variant="subtitle1">Scan Depth:</Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>{formik.values.scanDepth} (out of 5)</Typography>
                    
                    <Typography variant="subtitle1">Vulnerability Types:</Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 2 }}>
                      {formik.values.vulnerabilityTypes.map((type) => (
                        <Chip key={type} label={type} size="small" />
                      ))}
                    </Box>
                    
                    <Typography variant="subtitle1">Authentication:</Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>
                      {formik.values.authType === 'none' ? 'No Authentication' : 
                       formik.values.authType === 'form' ? 'Form Authentication' : 
                       formik.values.authType === 'basic' ? 'HTTP Basic Authentication' : 'API Token'}
                    </Typography>
                    
                    <Typography variant="subtitle1">Request Rate:</Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>{formik.values.requestsPerSecond} requests per second</Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
            
            {scanStarted ? (
              <Box sx={{ mt: 4, textAlign: 'center' }}>
                <CircularProgress variant="determinate" value={scanProgress} size={80} thickness={4} />
                <Typography variant="h6" sx={{ mt: 2 }}>{scanStatus}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {scanProgress}% Complete
                </Typography>
                <Box sx={{ mt: 2 }}>
                  <Button
                    variant="outlined"
                    color="warning"
                    startIcon={<PauseIcon />}
                    sx={{ mr: 1 }}
                  >
                    Pause
                  </Button>
                  <Button
                    variant="outlined"
                    color="error"
                    startIcon={<StopIcon />}
                  >
                    Stop
                  </Button>
                </Box>
              </Box>
            ) : null}
          </Box>
        );
      default:
        return 'Unknown step';
    }
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        New Security Scan
      </Typography>
      
      <Paper sx={{ p: 3, mb: 4 }}>
        <Stepper activeStep={activeStep} alternativeLabel>
          {steps.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>
      </Paper>
      
      <Paper sx={{ p: 3 }}>
        <form onSubmit={formik.handleSubmit}>
          {getStepContent(activeStep)}
          
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
            <Button
              disabled={activeStep === 0 || scanStarted}
              onClick={handleBack}
              variant="outlined"
            >
              Back
            </Button>
            <Box>
              {activeStep === steps.length - 1 ? (
                <Button
                  variant="contained"
                  color="primary"
                  type="submit"
                  disabled={scanStarted}
                  startIcon={<PlayArrowIcon />}
                >
                  Start Scan
                </Button>
              ) : (
                <Button
                  variant="contained"
                  onClick={handleNext}
                  disabled={scanStarted}
                >
                  Next
                </Button>
              )}
            </Box>
          </Box>
        </form>
      </Paper>
    </Box>
  );
};

export default ScanConfiguration;
