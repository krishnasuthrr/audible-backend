import "dotenv/config"
import app from "./src/app.js";
import connectDB from "./src/db/db.js";

const startServer = async () => {

    try {
        
        const PORT = process.env.PORT || 3000;

        connectDB();

        const server = app.listen(PORT, () => {
          console.log(`Server Running on Port: ${PORT}`);
        });

        process.on("SIGINT", () => {  // Handling a Manual Server Termination, Graceful Shutdown
            console.log("Shutting Down Server...");
            server.close(() => {  // Executes after all currently active requests are completed
                console.log("Process Terminated");
                process.exit(0)
            })
        })

    } catch (error) {
        console.error("Failed to Start Server: ", error)
        process.exit(1)
    }

}

startServer();