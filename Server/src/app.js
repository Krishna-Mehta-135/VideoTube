import express from "express";
import cors from "cors"
import cookieParser from "cookie-parser"

const app = express();

app.use(cookieParser())

app.use(cors ({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}))

app.use(express.json({limit: "16kb"}))
app.use(express.urlencoded({extended : true, limit: "16kb"}))
app.use(express.static("public"))
app.use(cookieParser());


//routes import

import router from './routes/user.routes.js'

//routes declaration

app.use("/api/v1/users" ,router)
//It passes the control to the user router

export {app};
