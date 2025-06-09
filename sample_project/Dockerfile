# Sample Dockerfile with security issues for DevOps Buddy testing

# Using an outdated base image - security issue!
FROM node:14

# Running as root user - security issue!
# USER node should be used instead

# Working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy application code
COPY . .

# Expose port
EXPOSE 3000

# No health check defined - best practice issue
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#   CMD curl -f http://localhost:3000/health || exit 1

# Start the application
CMD ["npm", "start"] 