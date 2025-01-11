import { RequestHandler } from "express";
import createHttpError from "http-errors";
import UserModel from "../models/User";
import VerifyModel from "../models/Verification"
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { SendMail, sendResetPasswordEmail } from "../utils/sendEmails";
import { getAff, generateUniqueUsername, checkValidEmail } from "../utils/signupUtils";
import {getConfig} from '../init'
import { Config } from "../types";






//token-authenticaion

interface JwtPayload {
    id: string;
}

  
export const authenticate:RequestHandler = async (req,res,next) => {
    const config:Config = getConfig();
    try {
      const authHeader = req.headers.authorization;
  
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw createHttpError(404,'No token Found')
      }
  
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, config.jwtSecret!) as JwtPayload;
      const user = await UserModel.findOne({_id:decoded.id}).exec();
      if (!user || !user.is_verified) {
        throw createHttpError(404, 'User Not Found')
      }
      
      const responsez = {
        username:user.username,
        aff:user.aff,
        profile:user.profileImg
      }
      res.status(200).json(responsez)

    } catch (err) {
      next(err)
    }
  };




interface SignUpBody{
    email?:string,
    password?:string,
    image_url?:string,
    username?:string
}


//sign-up function



export const signUp: RequestHandler<unknown, unknown, SignUpBody, unknown> = async (req, res, next) => {
    const email = req.body.email;
    const passwordRaw = req.body.password;
    let username = req.body.username;
    let profileImg = req.body.image_url;


    try {
        if ( !email || !passwordRaw) {
            throw createHttpError(400, "Parameters missing");
        }

        const isvalidEm = checkValidEmail(email)
        if(!isvalidEm){
            throw createHttpError(401,'Not a valid email that we support as of now')
        }



        const existingUser = await UserModel.findOne({ email: email }).exec();

        if (existingUser) {
            if (existingUser.is_verified){
                throw createHttpError(409, "User is already regsistered with this email")
            }

            const VerStatus = await VerifyModel.findOne({email:email}).exec()
            if (VerStatus){
                throw createHttpError(501, "User is Registred, check your inbox for verification email")
            }

            await VerifyModel.create({
                email:email
            })

            
            await SendMail(email);
            res.status(200).json({ message: "Verification email sent. Please check your inbox." });
            

        }


        const passwordHashed = await bcrypt.hash(passwordRaw, 10);
        if(!username){
            username = await generateUniqueUsername()
        }
        if(!profileImg){
            profileImg = `https://robohash.org/${username}.png`
        }
        const aff = getAff(email)
        const newUser = await UserModel.create({
            username: username,
            email: email,
            password: passwordHashed,
            is_verified:false,
            profileImg:profileImg,
            aff:aff
        });

        await VerifyModel.create({
            email:email
        })

        await SendMail(email);
        res.status(200).json({ message: "User Registered and Verification email sent. Please check your inbox." });

    } catch (error) {
        next(error);
    }
};







//Login Function

interface LoginBody{
    email?:string,
    password?:string
}



export const Login:RequestHandler<unknown, unknown, LoginBody, unknown> = async(req,res,next)=>{
    const email = req.body.email
    const pass = req.body.password
    const config:Config = getConfig();

    try {
        if (!pass || !email){
            throw createHttpError(404, 'Incomplete Credentials')
        }
        
        const User = await UserModel.findOne({email:email}).exec()
        if(!User || !User.is_verified){
            throw createHttpError(401, "User Does not exist or Verified")
        }
        const ismatch = await bcrypt.compare(pass,User.password!)
        if(!ismatch){
            throw createHttpError(404, "Invalid Password")
        }
        
        const id = User._id
        const user = {
            username:User.username,
            aff:User.aff,
            profile:User.profileImg
        }
        const token =  jwt.sign({id},config.jwtSecret!, { expiresIn: '336h' })
        res.status(200).json({ user, token });

    } catch (error) {
        next(error)
    }


}







//verification of email

interface verifyParams{
    token:string
}

export const VerifyEmail :RequestHandler<verifyParams,unknown,unknown,unknown> = async(req,res,next)=>{
    const {token} = req.params
    const config:Config = getConfig();
    try {
        
        
        const decoded = jwt.verify(token,config.jwtSecret) as {email:string}
        const User = await UserModel.findOne({email:decoded.email}).exec()
        if(!User){
            throw createHttpError(404, 'No User Registered')
        }
        if(User.is_verified){
            throw createHttpError(400, 'User Already Verified')
        }
        const verification = await VerifyModel.findOne({email:decoded.email})
        if (!verification){
            throw createHttpError(401, "Token has expired, Request Again Through Signup.")
        }
        

        User.is_verified = true

        await User.save()

        await VerifyModel.deleteOne({email:decoded.email}).exec()

        const id = User._id
        const user = {
            username:User.username,
            aff:User.aff,
            profile:User.profileImg
        }
        const token_id =  jwt.sign({id}, config.jwtSecret!, { expiresIn: '336h' })
        res.status(200).json({ message:"User is Verified, You can now Login", user, token_id });
    

    } catch (error) {
        next(error)
    }
}







//Forget-email


interface ForgotPasswordBody {
    email?: string;
}


export const forgotPassword: RequestHandler<unknown, unknown, ForgotPasswordBody, unknown> = async (req, res, next) => {
    const email = req.body.email;
    const config:Config = getConfig();
    try {
        if (!email) {
            throw createHttpError(400, "Email is required");
        }

        const user = await UserModel.findOne({ email: email, is_verified: true }).exec();
        if (!user) {
            throw createHttpError(404, "No verified user found with this email");
        }

        const resetToken = jwt.sign(
            { userId: user._id },
            config.jwtSecret,
            { expiresIn: '1h' }
        );

        await sendResetPasswordEmail(email, resetToken);

        res.status(200).json({
            message: "Password reset link has been sent to your email"
        });

    } catch (error) {
        next(error);
    }
};






//Handle password reset



interface ResetPasswordBody {
    newPassword?: string;
}

export const resetPassword: RequestHandler<verifyParams, unknown, ResetPasswordBody, unknown> = async (req, res, next) => {
    const {newPassword } = req.body;
    const {token} = req.params;
    const config:Config = getConfig();

    try {
        if (!token || !newPassword) {
            throw createHttpError(400, "Token and new password are required");
        }

        const decoded = jwt.verify(token, config.jwtSecret!) as { userId: string };

        const user = await UserModel.findById(decoded.userId).exec();
        if (!user) {
            throw createHttpError(404, "User not found");
        }
        const passwordHashed = await bcrypt.hash(newPassword, 10);

        user.password = passwordHashed;
        await user.save();

        res.status(200).json({
            message: "Password has been successfully reset"
        });


    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            next(createHttpError(401, "Reset token has expired"));
        } else if (error instanceof jwt.JsonWebTokenError) {
            next(createHttpError(401, "Invalid reset token"));
        } else {
            next(error);
        }
    }
};








// change password


interface ChangePasswordBody {
    currentPassword: string;
    newPassword: string;
}

export const changePassword: RequestHandler<unknown, unknown, ChangePasswordBody, unknown> = async (req, res, next) => {
    const { currentPassword, newPassword } = req.body;
    const authHeader = req.headers.authorization;
  
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw createHttpError(404,'No token Found')
      }
  
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;
    const userId = decoded.id

    try {
        if (!currentPassword || !newPassword) {
            throw createHttpError(400, "Current password and new password are required");
        }

        const user = await UserModel.findById(userId).exec();
        if (!user) {
            throw createHttpError(404, "User not found");
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password!);
        if (!isMatch) {
            throw createHttpError(401, "Current password is incorrect");
        }

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();

        res.status(200).json({
            message: "Password has been successfully changed"
        });

    } catch (error) {
        next(error);
    }
};



//update profile


interface UpdateUserProfileBody {
    username?: string;
    profileImg:string
    
}

export const updateUserProfile: RequestHandler<unknown, unknown, UpdateUserProfileBody, unknown> = async (req, res, next) => {
    const { username, profileImg } = req.body;
    const authHeader = req.headers.authorization;
  
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw createHttpError(404,'No token Found')
      }
  
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;
    const userId = decoded.id 

    try {
        const user = await UserModel.findById(userId).exec();
        if (!user) {
            throw createHttpError(404, "User not found");
        }

        if (username) user.username = username;
        if (profileImg) user.profileImg = profileImg;
       

        await user.save();

        res.status(200).json({
            message: "Profile has been successfully updated",
            user
        });

    } catch (error) {
        next(error);
    }
};
