import mongoose from "mongoose";

export default async function connectDB() {
    try {

        const conn = await mongoose.connect(process.env.MONGO_URI, {
          serverSelectionTimeoutMS: 5000,
        });
        console.log("Database Connected Successfully: ", conn.connection.host) 

    } catch (error) {
        console.error("Database Connection Error: ", error)

        process.exit(1) // Shut Down / Terminate server Intentionally
    } 
}