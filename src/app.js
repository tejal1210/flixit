import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import morgan from "morgan";

const app = new express();

// app.use(
//     cors({
//         origin: process.env.CORS_ORIGIN,
//         credentials: true,
//     })
// );

// const corsOptions = {
//     origin: 'http://localhost:5173', // Adjust this to your frontend origin
//     credentials: true,               // Allow credentials
//   };
  const corsOptions = {
    origin:  process.env.CORS_ORIGIN, // Adjust this to your frontend origin
    credentials: true,               // Allow credentials
  };
app.use(cors(corsOptions));

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));
app.use(express.static("public"));
app.use(cookieParser());
app.use(morgan("dev")); //HTTP request logger middleware for node.js 

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', 'http://localhost:5173'); // The origin you want to allow
    res.header('Access-Control-Allow-Credentials', 'true');            // Allow credentials
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH'); // Other headers as needed
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');     // Other headers as needed
    next();
  });

//routes import

import userRouter from "./routes/user.routes.js";
import commentRouter from "./routes/comment.routes.js";
import likeRouter from "./routes/like.routes.js";
import subscriptionRouter from "./routes/subscription.routes.js";
import tweetRouter from "./routes/tweet.routes.js";
import videoRouter from "./routes/video.routes.js";
import healthcheckRouter from "./routes/healthcheck.routes.js";
import playlistRouter from "./routes/playlist.routes.js";
import dashboardRouter from "./routes/dashboard.routes.js";

//routes declaration
app.use("/api/v1/users", userRouter);
app.use("/api/v1/comment", commentRouter);
app.use("/api/v1/likes", likeRouter);
app.use("/api/v1/subscriptions", subscriptionRouter);
app.use("/api/v1/tweet", tweetRouter);
app.use("/api/v1/video", videoRouter);
app.use("/api/v1/healthcheck", healthcheckRouter);
app.use("/api/v1/playlist", playlistRouter);
app.use("/api/v1/dashboard", dashboardRouter);


export default app;