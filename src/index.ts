import { Router } from 'express';
import { Config } from './types';
import { init } from './init';
export * from './types';
import * as UserController from "./controllers/UserController"
import mongoose from 'mongoose';
import { requiresAuth } from "./middlewares/auth";


let isConnected = false

async function connectDB(mongoUrl:string) {
  if (isConnected) {
    console.log('MongoDB is already connected');
    return;
  }

  try {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(mongoUrl);
    isConnected = true;
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
    throw error; 
  }
}

export function createAuthRouter(config:Config):Router{

  if (!config.mongoUrl) {
    throw new Error('mongoURI is required in the configuration');
  }

  connectDB(config.mongoUrl)
    .then(() => console.log('Database connection ready for auth router'))
    .catch((err) => console.error('Database connection failed:', err));

  init(config)
  const router = Router()

  router.get('/',requiresAuth,UserController.authenticate)
  router.post('/signup',UserController.signUp)
  router.get('/verify_email/:token',UserController.VerifyEmail)
  router.post('/login',UserController.Login)
  router.post('/forget_password',requiresAuth, UserController.forgotPassword)
  router.post('/reset_password/:token',UserController.resetPassword)
  router.patch('/change_password',requiresAuth,UserController.changePassword)
  router.patch('/update_user_profile',requiresAuth,UserController.updateUserProfile)

  return router
  
}






