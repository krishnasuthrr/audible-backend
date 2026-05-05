import userModel from "../models/userModel.js";
import { usernameValidator, emailValidator, cleanUserInput } from "../utils/inputValidators.js";
import passwordValidator from "../utils/passwordValidator.js";
import sessionModel from "../models/sessionModel.js";
import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs";
import crypto from "crypto"

async function registerUser(req, res) {
    
    try {

        let { username, email, password } = req.body
    
        if (!username || !email || !password) {
            return res.status(400).json({ message: "Invalid Credentials: missing required Input(s)" })
        }

        username = cleanUserInput(username)
        email = cleanUserInput(email)

        if (!usernameValidator(username)) {  // Validator is a Util which sanitizes and validates inputs
            return res.status(400).json({ message: "Username must only contain Alphabets and not Special Characters" })
        }
        if(!emailValidator(email)) {
            return res.status(400).json({ message: "Invalid Email format" })
        }
       
        const passwordErrors = passwordValidator(password)
        if(passwordErrors.length > 0){
            return res.status(400).json({ errors: passwordErrors })
        }
    
        const existingUser = await userModel.findOne({
          $or: [
            { username: username.toLowerCase() },
            { email }
        ],
        });
    
        if(existingUser) {
            return res.status(409).json({ message: "Username or Email is already registered" })
        }
    
        const hashedPassword = await bcrypt.hash(password, 10);
    
        const user = await userModel.create({
            username: username.toLowerCase(),
            email: email.toLowerCase(),
            password: hashedPassword
        })

        const session = await sessionModel.create({
          userId: user._id,
          ip: req.ip,
          userAgent: req.headers["user-agent"] || "Unknown Device",
          expiresAt: new Date(Date.now() + expirationTime),
        });

        const refreshToken = jwt.sign(
          {
            id: user._id,
            role: user.role,
            sessionID: session._id
          },
          process.env.JWT_REFRESH_SECRET,
          {
            expiresIn: "7d",
          },
        );

        const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex")
        const expirationTime = 1000 * 60 * 60 * 24 * 7;

        session.refreshTokenHash = refreshTokenHash
        await session.save()

        const cookieOptions = {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "Strict", 
          maxAge: expirationTime, 
          path: "/",
        };

        res.cookie("refreshToken", refreshToken, cookieOptions);

        const accessToken = jwt.sign({
            userID: user._id,
            role: user.role,
            sessionID: session._id
        }, process.env.JWT_ACCESS_SECRET, {
            expiresIn: "15m"
        })
    
        return res.status(201).json({ message: "User Registered Successfully",
            user: {
                id: user._id,
                accessToken
            }
        })
    
    } catch (error) {
        console.error(error)
        return res.status(500).json({ message: "Internal Server Error" })
    }

}

async function loginUser(req, res) {

    try {

        const { identifier, password } = req.body;
        let user
    
        if(!identifier) {
            return res.status(400).json({ message: "Either Username or Email required" })
        }
        if(!password) {
            return res.status(400).json({ message: "Enter the Password" })
        }
    
        if(usernameValidator(identifier)) {
            user = await userModel.findOne({ username: identifier })
        }
        if(emailValidator(identifier)) {
            user = await userModel.findOne({ email: identifier })
        }
    
        if(!user) {
            return res.status(401).json({ message: "User not Found" })
        }
    
        const isPasswordCorrect = await bcrypt.compare(password, user.password)
    
        if(!isPasswordCorrect) {
            return res.status(401).json({ message: "Incorrect Password" })
        }
    
        const token = jwt.sign({
            id: user._id,
            role: user.role
        }, process.env.JWT_SECRET, {
            expiresIn: "1d"
        })
    
        const cookieOptions = {
          httpOnly: true,
          sameSite: "Strict", 
          maxAge: 1000 * 60 * 60 * 24 * 7,
          path: "/",
        };
    
        res.cookie("token", token, cookieOptions);
    
        return res.status(201).json({
          message: "User Logged In Successfully",
          user: {
              id: user._id,
              token,
          },
        });

    } catch (error) {
        return res.status(500).json({ message: "Internal Server Error" })
    }

}

const authControllers = {
    registerUser,
    loginUser
}

export default authControllers