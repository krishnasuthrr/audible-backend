import express from "express"
import authControllers from "../controllers/authControllers.js"
import { authenticateUser } from "../middlewares/authenticateUser.js";

const authRouter = express.Router()

authRouter.post("/register", authControllers.registerUser);
authRouter.post("/login", authControllers.loginUser)

export default authRouter;