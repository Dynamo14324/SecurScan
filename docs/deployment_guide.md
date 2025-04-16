# SecurScan Deployment Guide

## Overview

This guide provides instructions for deploying the SecurScan security testing platform. The platform consists of a React frontend and a Node.js backend.

## Prerequisites

- Node.js v16.x or higher
- npm v7.x or higher
- MongoDB (for production deployment)

## Local Development Setup

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file based on the `.env.example`:
   ```bash
   cp .env.example .env
   ```

4. Start the development server:
   ```bash
   npm run dev
   ```

The backend server will run on http://localhost:5000 by default.

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm start
   ```

The frontend development server will run on http://localhost:3000 by default.

## Production Deployment

### Backend Deployment

1. Set up environment variables for production:
   ```
   PORT=5000
   NODE_ENV=production
   MONGODB_URI=your_mongodb_connection_string
   JWT_SECRET=your_secure_jwt_secret
   JWT_EXPIRATION=1d
   ```

2. Build and start the backend:
   ```bash
   cd backend
   npm install
   npm start
   ```

### Frontend Deployment

1. Build the frontend for production:
   ```bash
   cd frontend
   npm install
   npm run build
   ```

2. Serve the static files using a web server like Nginx or Apache, or use a static hosting service.

## Docker Deployment

A Docker Compose configuration is available for easy deployment:

1. Make sure Docker and Docker Compose are installed on your system.

2. Create a `.env` file in the root directory with the necessary environment variables.

3. Build and start the containers:
   ```bash
   docker-compose up -d
   ```

## Cloud Deployment

### Current Deployment

The SecurScan platform is currently deployed at:
https://wiyxmvfp.manus.space

This is a static deployment of the frontend application. For a full production deployment, you would need to:

1. Deploy the backend to a server or cloud service (AWS, Azure, GCP)
2. Configure the frontend to connect to the deployed backend
3. Set up a database (MongoDB) for persistent storage

### Deployment Options

1. **AWS Deployment**:
   - Deploy backend to EC2 or Elastic Beanstalk
   - Deploy frontend to S3 + CloudFront
   - Use MongoDB Atlas or DocumentDB for the database

2. **Azure Deployment**:
   - Deploy backend to App Service
   - Deploy frontend to Static Web Apps
   - Use Cosmos DB for the database

3. **GCP Deployment**:
   - Deploy backend to App Engine or Cloud Run
   - Deploy frontend to Firebase Hosting
   - Use MongoDB Atlas for the database

## Troubleshooting

- **CORS Issues**: Ensure the backend has proper CORS configuration to allow requests from the frontend domain.
- **Database Connection**: Verify MongoDB connection string and credentials.
- **Environment Variables**: Check that all required environment variables are set correctly.
- **Port Conflicts**: Make sure the specified ports are not in use by other applications.

## Maintenance

- Regularly update dependencies to patch security vulnerabilities.
- Monitor server logs for errors and performance issues.
- Perform regular backups of the database.
- Set up monitoring and alerting for the application.
