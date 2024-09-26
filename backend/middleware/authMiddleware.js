import jwt from 'jsonwebtoken';
import asyncHandler from 'express-async-handler';
import User from '../models/userModel.js';

const throwError = (res, message, status = 401) => {
  res.status(status);
  throw new Error(message);
};

const protect = asyncHandler(async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer')) {
    throwError(res, 'Not authorized, no token');
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select('-password');

    if (!req.user) {
      throwError(res, 'Not authorized, user not found');
    }
    
    next();
  } catch (error) {
    console.error(error);
    throwError(res, 'Not authorized, token failed');
  }
});

const authorizeRole = (role) => (req, res, next) => {
  if (req.user && req.user[role]) {
    return next();
  }
  throwError(res, `Not authorized as ${role}`);
};

const admin = authorizeRole('isAdmin');
const admin_seller = authorizeRole('isAdminSeller');
const admin_or_seller = (req, res, next) => {
  if (req.user && (req.user.isAdmin || req.user.isAdminSeller)) {
    return next();
  }
  throwError(res, 'Not authorized as an admin or seller');
};

export { protect, admin, admin_seller, admin_or_seller };
