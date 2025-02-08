import express from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import cors from "cors";
// import ApiError from "../utilities/ApiError.js";
import bodyParser from "body-parser";
import morgan from "morgan";
// Import the network routes with correct path
import networkRoutes from "../routes/network.route.js";
import aptRoutes from "../routes/apt.route.js";
import phishingRoutes from "../routes/phishing.route.js";
import zeroDayRoutes from "../routes/zeroDay.route.js";
import dashboardRoutes from "../routes/dashboard.routes.js";
import threatRoutes from '../routes/threat.routes.js';
import vulnerabilityScanRoutes from '../routes/vulnerabilityScan.routes.js';
import networkAdvancedRoutes from '../routes/networkAdvanced.routes.js';

dotenv.config();

const app = express();   
const port = process.env.PORT || 3041;

app.use(cors({
  origin: '*',
  credentials: true,
}));

app.set("trust proxy", true);
app.use(morgan('dev'));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

// Mount the network routes
app.use("/api/v1/network", networkRoutes);
app.use('/api/v1/apt',aptRoutes);
app.use('/api/v1/phishing', phishingRoutes);
app.use('/api/v1/zeroDay', zeroDayRoutes);
app.use("/api/v1/dashboard", dashboardRoutes);
app.use('/api/v1/threat-analysis', threatRoutes);
app.use('/api/v1/vulnerability', vulnerabilityScanRoutes);
app.use('/api/v1/advanced-network',networkAdvancedRoutes);


// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(err.statusCode || 500).json({
        success: false,
        message: err.message || "Internal Server Error",
        errors: err.errors || []
    });
});

// Health check route
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'Server is running'
    });
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

export default app;


