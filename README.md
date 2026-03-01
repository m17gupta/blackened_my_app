# E-commerce Node.js Express Server (TypeScript)

This is a modern Node.js Express server built with TypeScript, Mongoose, and JWT authentication. It is designed to work as the backend for the `my-App` mobile application.

## Features

- **TypeScript**: Typed development with TSX for fast development.
- **Express**: Fast, unopinionated, minimalist web framework.
- **MongoDB**: Database integration using Mongoose.
- **JWT Auth**: Secure authentication for user registration and login.
- **ESM**: Using ES Modules (`type: module`).

## Prerequisites

- **Node.js**: v18+ recommended.
- **MongoDB**: A running instance (local or MongoDB Atlas).

## Getting Started

1. **Install Dependencies**:

   ```bash
   cd server
   npm install
   ```

2. **Configure Environment**:
   Update the `.env` file with your credentials:

   ```env
   PORT=5000
   MONGODB_URI=your_mongodb_uri
   JWT_SECRET=your_jwt_secret
   ```

3. **Run Development Server**:

   ```bash
   npm run dev
   ```

4. **Build and Start (Production)**:
   ```bash
   npm run build
   npm start
   ```

## API Endpoints

- `POST /api/users`: Combined Register/Login endpoint (matching the mobile app logic).
- `GET /api/users`: List all users (for admin/testing).
- `GET /`: Health check.

## Directory Structure

- `src/index.ts`: Entry point.
- `src/config/`: Database configuration.
- `src/controllers/`: Business logic.
- `src/models/`: Mongoose schemas and TypeScript interfaces.
- `src/routes/`: Express route definitions.
- `src/middlewares/`: Auth and utility middlewares.
