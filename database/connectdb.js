import mongoose from 'mongoose'
// import { DB_NAME } from '../src/constant.js'
const connectDB=async()=>{
    try {
        // mongodb+srv://ddo:<db_password>@cluster0.yx4ct.mongodb.net/
        // console.log(`mongodb+srv://${process.env.MNAME}:${process.env.MPASSWORD}@cluster0.o3kp0fp.mongodb.net/videotube`);
        const Connection=await mongoose.connect(`mongodb+srv://ddo:ddoddo@cluster0.yx4ct.mongodb.net/`)
        console.log(`your database is connected to the ${Connection.connection.host}`)

    } catch (error) {
        console.log(error);
        process.exit(1)
        
    }
}
// mongodb+srv://ANSH_39:ansh3931@cluster0.o3kp0fp.mongodb.net//lms
export default connectDB;