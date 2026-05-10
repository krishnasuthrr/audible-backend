import userModel from "../models/userModel.js";
import { usernameValidator, emailValidator, cleanUserInput } from "../utils/inputValidators.js";
import passwordValidator from "../utils/passwordValidator.js";
import sessionModel from "../models/sessionModel.js";
import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs";
import crypto from "crypto"
import { ref } from "process";

async function getUser(req, res) {
    
    try {
        
        const decoded = req.user

        const user = await userModel.findById(decoded.userID)

        if(!user) {
            return res.status(401).json({ message: "Unauthorized" })
        }

        return res.status(200).json({
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        })

    } catch (error) {
        console.log("Error Getting user: ", error)
        return res.status(500).json({ message: "Internal Server Error" })
    }

}

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
            return res.status(400).json({ passwordErrors: passwordErrors })
        }
    
        const existingUser = await userModel.findOne({
          $or: [
            { username },
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

        const expirationTime = 1000 * 60 * 60 * 24 * 7;

        const session = await sessionModel.create({
          userId: user._id,
          ip: req.ip,
          refreshTokenHash: "null",
          userAgent: req.headers["user-agent"] || "Unknown Device",
          expiresAt: new Date(Date.now() + expirationTime),
        });

        const refreshToken = jwt.sign(
          {
            id: user._id,
            sessionID: session._id
          },
          process.env.JWT_REFRESH_SECRET,
          {
            expiresIn: "7d",
          },
        );

        const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

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

        if(error.name === "ValidationError") {
            return res.status(400).json({ message: "Data Validation Error" })
        }

        if (error.code === 11000) {
            return res.status(409).json({ message: "Username or Email already exists" });
        }

        return res.status(500).json({ message: "Internal Server Error" })
    }

}

async function loginUser(req, res) {

    try {

        let { identifier, password } = req.body;
        let user
    
        if(!identifier) {
            return res.status(400).json({ message: "Either Username or Email required" })
        }
        if(!password) {
            return res.status(400).json({ message: "Enter the Password" })
        }

        identifier = cleanUserInput(identifier);
    
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

        const expirationTime = 1000 * 60 * 60 * 24 * 7

        const session = await sessionModel.create({
            userId: user._id,
            refreshTokenHash: "null",
            ip: req.ip,
            userAgent: req.headers[ "user-agent" ],
            expiresAt: new Date(Date.now() + expirationTime)
        })

        const refreshToken = jwt.sign(
        {
            userID: user._id,
            sessionID: session._id
        },
        process.env.JWT_REFRESH_SECRET,
        {
            expiresIn: "7d",
        },
        );

        const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

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

        const accessToken = jwt.sign(
          {
            userID: user._id,
            role: user.role,
            sessionID: session._id,
          },
          process.env.JWT_ACCESS_SECRET,
          {
            expiresIn: "15m",
          },
        );
    
        return res.status(200).json({
          message: "User Logged In Successfully",
          user: {
              id: user._id,
              accessToken
          },
        });

    } catch (error) {
        console.error(error)

        if (error.name === "ValidationError") {
          return res.status(400).json({ message: "Data Validation Error" });
        }

        return res.status(500).json({ message: "Internal Server Error" })
    }

}

async function logout(req, res) {
    
    try {
        
        const refreshToken = req.cookies.refreshToken

        if (!refreshToken) {
          return res.status(200).json({ message: "Logged out" });
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET)

        res.clearCookie("refreshToken")

        const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex")

        const session = await sessionModel.findOne({
            userId: decoded.userID,
            _id: decoded.sessionID
        })

        if (!session || session.refreshTokenHash !== refreshTokenHash) {
            return res.status(403).json({ message: "Request Forbidden" });
        }

        session.revoked = true;
        await session.save();

        return res.status(200).json({ message: "Logged Out" })

    } catch (error) {
        console.error(error)

        if (
          error.name === "JsonWebTokenError" ||
          error.name === "TokenExpiredError"
        ) {
          return res.status(401).json({ message: "Invalid Token" });
        }

        return res.status(500).json({ message: "Internal Server Error" })
    }

}

async function logoutAll(req, res) {
    
    try {
        
        const refreshToken = req.cookies.refreshToken

        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET)

        res.clearCookie("refreshToken")

        const session = await sessionModel.updateMany(
            { userId: decoded.userID, revoked: false },
            { 
                $set: { revoked: true } 
            }
        )

        return res.status(200).json({ message: "Logged out of all Devices" })

    } catch (error) {
        console.error(error)

        if (
          error.name === "JsonWebTokenError" ||
          error.name === "TokenExpiredError"
        ) {
          return res.status(401).json({ message: "Invalid Token" });
        }

        return res.status(500).json({ message: "Internal Server Error" })
    }

}


async function generateRefreshToken(req, res) {
    
    try {

        const refreshToken = req.cookies.refreshToken

        const decoded = req.user
    
        const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex")
    
        const user = await userModel.findById(decoded.userID)
    
        if(!user) {
            return res.status(401).json({ message: "Unauthorized User" })
        }
    
        const session = await sessionModel.findOne({
          userId: decoded.userID,
          _id: decoded.sessionID,
        });
    
        if(!session || (session.refreshTokenHash !== refreshTokenHash)) {
            return res.status(403).json({ message: "Request Forbidden" })
        }
    
        res.clearCookie("refreshToken")
    
        const expirationTime = 1000 * 60 * 60 * 24 * 7
    
        const newRefreshToken = jwt.sign(
            {
                userID: decoded.userID,
                sessionID: decoded.sessionID
            },
            process.env.JWT_REFRESH_SECRET,
            {
                expiresIn: "7d"
            }
        )
    
        const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex")
    
        session.refreshTokenHash = newRefreshTokenHash
        session.expiresAt = new Date( Date.now() + expirationTime )
        await session.save()
    
        const cookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "Strict",
            maxAge: expirationTime,
            path: "/"
        }
    
        res.cookie("refreshToken", newRefreshToken, cookieOptions)
    
        const newAccessToken = jwt.sign(
          {
            userID: decoded.userID,
            sessionID: decoded.sessionID,
            role: user.role
          },
          process.env.JWT_REFRESH_SECRET,
          {
            expiresIn: "15m",
          },
        );
    
        return res.status(200).json({
            message: "Success",
            newAccessToken
        })
    } catch (error) {
        console.error("error rotating refresh token: ", error)

        return res.status(500).json({ message: "Internal Server Error" })
    }

}

const authControllers = {
    getUser,
    registerUser,
    loginUser,
    generateRefreshToken,
    logout,
    logoutAll,
}

export default authControllers