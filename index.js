import dontenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import connectDB from './config/connectdb.js';
import userRoutes from './routes/useRoutes.js'
// to make all the data accessible which are under .env folder
dontenv.config(); 

const app = express();
const port = process.env.PORT;
const DATABASE_URL = process.env.DATABASE_URL;

//Cors policy
app.use(cors());
  
//Database Connection
connectDB(DATABASE_URL);

//JSON
app.use(express.json());

// Load Routes
app.use('/api/user', userRoutes);

app.listen(port, () =>{
    console.log(`Server is running at http://localhost:${port}`);
});