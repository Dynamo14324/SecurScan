import React from 'react';
import { Box, Typography, Container, Paper } from '@mui/material';

const NotFound = () => {
  return (
    <Container maxWidth="md">
      <Paper sx={{ p: 4, mt: 8, textAlign: 'center' }}>
        <Typography variant="h1" component="h1" gutterBottom>
          404
        </Typography>
        <Typography variant="h4" component="h2" gutterBottom>
          Page Not Found
        </Typography>
        <Typography variant="body1" paragraph>
          The page you are looking for does not exist or has been moved.
        </Typography>
        <Box mt={4}>
          <Typography variant="body2" color="text.secondary">
            Please check the URL or navigate back to the dashboard.
          </Typography>
        </Box>
      </Paper>
    </Container>
  );
};

export default NotFound;
