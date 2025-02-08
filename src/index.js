import dotenv from 'dotenv';
import app from './app.js';
import  connectDB  from '../database/connectdb.js';

dotenv.config();

const startServer = async () => {
    try {
        await connectDB();
        
        const port = process.env.PORT || 3014;
        
        // Check if port is in use
        const server = app.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });

        server.on('error', (error) => {
            if (error.code === 'EADDRINUSE') {
                console.log(`Port ${port} is busy, trying ${port + 1}`);
                server.listen(port + 1);
            } else {
                console.error('Server error:', error);
            }
        });

    } catch (error) {
        console.error("DB Connection failed:", error);
        process.exit(1);
    }
};

startServer();