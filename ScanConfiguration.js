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
             
(Content truncated due to size limit. Use line ranges to read in chunks)