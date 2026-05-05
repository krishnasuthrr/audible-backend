import jwt from "jsonwebtoken"

export function authenticateUser(req, res, next) {

    try {

        const token = req.cookies.token
    
        if(!token) {
            return res.status(401).json({ message: "Unauthorized user, kindly Login or Register" })
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