# Use a lightweight Node.js image
FROM node:22-alpine AS base

# Create and set the working directory inside the container
WORKDIR /usr/src/app

# Copy package files first (for better build caching)
COPY package*.json ./

# Install only production dependencies (change if you need dev ones)
RUN npm install --omit=dev

# Copy the rest of the project files
COPY . .

# Expose the port your app runs on (adjust if not 3000)
EXPOSE 5000

# Start the app
CMD ["node", "app.js"]
