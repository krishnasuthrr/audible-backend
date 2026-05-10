import express from "express"
import authControllers from "../controllers/authControllers.js"
import { authenticateUser, verifyRefreshToken } from "../middlewares/authenticateUser.js";

const authRouter = express.Router()

authRouter.get("/get-user", verifyRefreshToken, authControllers.getUser)
authRouter.post("/register", authControllers.registerUser);
authRouter.post("/login", authControllers.loginUser);
authRouter.post("/logout", authControllers.logout);
authRouter.post("/logout-all", authControllers.logoutAll)
authRouter.post("/refresh-token", verifyRefreshToken, authControllers.generateRefreshToken);

export default authRouter;