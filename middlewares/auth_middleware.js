import jwt from "jsonwebtoken";
import User from "../models/User.js";

// middelware function to check whether the user is authorized
const checkUserAuth = async (req, res, next) =>{
    let token 

    // getting authorization from req.headers
    const {authorization} = req.headers;

    // checking whether autherization is there or not
    if(authorization && authorization.startsWith('Bearer')){
        try {
            // separating and getting the token as it is received like 'Bearer <token>'
            token = authorization.split(' ')[1];

            // Verify Token 
            const { userId } = jwt.verify(token, process.env.JWT_SECRET_KEY);

            // Get User from Token
            // it will return all the data of the user from mongoDB except the user password
            req.user = await User.findById(userId).select("-password");
            
            // passing the control to next controller
            next();
        } catch (error) {
            return res.status(401).send({"status": "failed", "message": "Unauthorized User."});
        }
    }
    // if not token is present
    if(!token){
        return res.status(401).send({ "status": "failed", "message": "Unauthorized User, No token." });
    }
}

export default checkUserAuth;