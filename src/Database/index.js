import mongoose from 'mongoose';

const DB_NAME = 'HelpDesk'

const connectDB = async () => {
    try {
        const connectionInstance = await mongoose.connect(`${process.env.MONGODB_URI}${DB_NAME}`)
        console.log(`mongodb connected !! DB HOST: ${connectionInstance.connection.host}`);
        
    } catch (error) {
        console.log("MONGODB conncetion error ", error);
        process.exit(1)
    }
}

export default connectDB