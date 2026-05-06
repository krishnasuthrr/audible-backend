import jwt from "jsonwebtoken"

export function authenticateUser(req, res, next) {

    try {

        const token = req.cookies.token
    
        if(!token) {
            return res.status(401).json({ message: "Unauthorized User" })
        }
    
        const decoded = jwt.verify(token, process.env.JWT_SECRET)

        req.user = decoded

        next()

    } catch (error) {
        console.error(error)
        if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
          return res.status(401).json({ message: "Invalid Token" });
        }

        return res.status(500).json({ message: "Internal Server Error" })
    }

}

export function verifyRefreshToken(req, res, next) {

    try {

        const refreshToken = req.cookies.refreshToken;
    
        if(!refreshToken) {
            return res.status(401).json({ message: "Unauthorized User" })
        }
    
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET)

        req.user = decoded

        next()

    } catch (error) {
        console.error("RefreshToken verification error: ", error);
        if (
          error.name === "JsonWebTokenError" ||
          error.name === "TokenExpiredError"
        ) {
          return res.status(401).json({ message: "Invalid Token" });
        }

        return res.status(500).json({ message: "Internal Server Error" });
    }

}