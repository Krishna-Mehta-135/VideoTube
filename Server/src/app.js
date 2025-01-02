import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}));

app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser());

// Add a test route to check the body parsing
// app.post('/test', (req, res) => {
//     console.log(req.body);  // This will log the body content of the incoming request
//     res.status(200).json({ message: 'Test route works' });
// });

// Routes import
import router from './routes/user.routes.js';

// Routes declaration
app.use("/api/v1/users", router);

export { app };
