
import connectDB from './Database/index.js';
import { app } from './app.js';
import dotenv from "dotenv";
dotenv.config({
    path: './.env'
}); 

connectDB()
.then(() => {
    app.listen(process.env.PORT || 8000,() => {
        console.log(`MongoDB connected successfully on the port ${process.env.PORT || 8000}`);
        
    })
})
.catch((error) => {
    console.log("MongoDB connection failed !!!", error)
})
