const express = require("express")
const app = express();

const userRoutes = require("./routes/User");
const profileRoutes = require("./routes/Profile");
const paymentRoutes = require("./routes/Payments");
const courseRoutes = require("./routes/Course");
const contactRoute = require("./routes/ContactUs")

const database = require("./config/database");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const {cloudinaryConnect} = require("./config/cloudinary");
const fileUpload = require("express-fileupload");
const dotenv = require("dotenv");

// Loading environment variables from .env file
dotenv.config();

const PORT = process.env.PORT || 4004;


//database connect
database.connect();

//middleware
app.use(express.json());
app.use(cookieParser());
app.use(
    cors({
       origin: "*",
       credentials: true
    })
)
app.use(
    fileUpload({
        useTempFiles: true,
        tempFileDir: "/temp"
    })
)

//cloudinary connection
cloudinaryConnect();


//routes
app.use("/api/v1/auth", userRoutes);
app.use("/api/v1/profile", profileRoutes);
app.use("/api/v1/course", courseRoutes);
app.use("/api/v1/payment", paymentRoutes);
app.use("/api/v1/contact", contactRoute);


//default route
app.get("/", (req, res)=>{
    return res.json({
        success: true,
        message: "Your server is up and running"
    });
});


app.listen(PORT, ()=>{
    console.log(`App is running at ${PORT}`)
})