import nodemailer from "nodemailer"
import { Config } from "../types"
import { getConfig } from "../init"
import jwt from "jsonwebtoken"




export const SendMail = async(email:string)=>{
    const config:Config = getConfig()

    const transporter = nodemailer.createTransport({
        service:'gmail',
        auth:{
            user:config.emailService.email,
            pass:config.emailService.password
        },
        tls: {
            rejectUnauthorized: false 
        }
    })

    const verificationToken = jwt.sign({ email },config.jwtSecret!, { expiresIn: '1h' });
    const verificationUrl = `${config.frontendUrl}/verify_account_email/${verificationToken}`;
    const mailOptions = {
            to: email,
            subject: 'Email Verification',
            text: `Click here to verify your email: ${verificationUrl}`,
            html: `
                <h2>Signup Request</h2>
                <p>To verify your email, click on the link below:</p>
                <a href="${verificationUrl}">Reset Password</a>
                <p>This link will expire in 1 hour.</p>
                <p>If you did not request this, please ignore this email.</p>
        `
    };

    await transporter.sendMail(mailOptions)
}







export const sendResetPasswordEmail = async (email:string, resetToken:string) => {
    const config:Config = getConfig()

    const transporter = nodemailer.createTransport({
        service:'gmail',
        auth:{
            user:config.emailService.email,
            pass:config.emailService.password
        },
        tls: {
            rejectUnauthorized: false 
        }
    })


    const resetUrl = `${config.frontendUrl}/reset_password/${resetToken}`;
    
    const mailOptions = {
        to: email,
        subject: 'Password Reset Request',
        text: `To reset your password, click on this link: ${resetUrl}\n\nThis link will expire in 1 hour.\n\nIf you did not request this, please ignore this email.`,
        html: `
            <h2>Password Reset Request</h2>
            <p>To reset your password, click on the link below:</p>
            <a href="${resetUrl}">Reset Password</a>
            <p>This link will expire in 1 hour.</p>
            <p>If you did not request this, please ignore this email.</p>
        `
    };


    await transporter.sendMail(mailOptions);
};



