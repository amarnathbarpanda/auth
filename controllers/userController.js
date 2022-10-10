import User from '../models/User.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';


export const userRegistration = async (req, res) => {
    const { name, email, password, password_confirmation, tc } = req.body;
    const user = await User.findOne({ email: email });
    // checking whether user already exists
    if (user) {
        return res.status(400).send({ "status": "failed", "message": "Email already exists." });
    }

    // user forgets to provide any of the required fields 
    if (!name && !email && !password && !password_confirmation && !tc) {
        return res.status(400).send({ "status": "failed", "message": "All fields are required." });
    }

    // password and confirm password doesn't match
    if (password !== password_confirmation) {
        return res.status(400).send({ "status": "failed", "message": "Password and confirm password doesn't match." });
    }

    try {

        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(password, salt);

        const newUser = await User.create({
            name: name,
            email: email,
            password: hashPassword,
            tc: tc
        });

        // Generating JWT Token
        const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET_KEY, { expiresIn: '5d' });

        return res.status(201).send({ "status": "success", "message": "Registration successful!", "token": token });

    } catch (error) {
        return res.status(500).send({ "status": "failed", "message": "Unable to Register." });
    }

}

export const userlogin = async (req, res) => {
    try {
        const { email, password } = req.body;

        // checking whether user provided the neccessari details
        if (!email && !password) {
            return res.status(400).send({ "status": "failed", "message": "All fields are required." });
        }

        // checking whether user has registerd or not
        const user = await User.findOne({ email: email });

        if (!user) {
            return res.status(400).send({ "status": "failed", "message": "You are not a Registered user." });
        }

        // comparing the password which has been entered by user and the password present in the database which user has given at the time of registration
        const isPasswordMatching = await bcrypt.compare(password, user.password);

        // checking what if the passwords or email doesn't match
        if ((user.email !== email) || !isPasswordMatching) {
            return res.status(400).send({ "status": "failed", "message": "Email or Password is not Valid." });
        }

        // Generating JWT Token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '5d' });

        // if all is well then allow the user to login
        return res.status(200).send({ "status": "success", "message": "Login Successful!.", "token": token });

    } catch (error) {
        return res.status(500).send({ "status": "failed", "message": "Unable to Login." });
    }
}

// change password feature for user after login
export const changeUserPassword = async (req, res) => {
    const { password, password_confirmation } = req.body;

    if (!password || !password_confirmation) {
        return res.status(400).send({ "status": "failed", "message": "All fields are required." });
    }

    if (password !== password_confirmation) {
        return res.status(400).send({ "status": "failed", "message": "New Password and Confirm New Password doesn't match." });
    }

    // password hashing
    const salt = await bcrypt.genSalt(10);
    const newHashPassword = await bcrypt.hash(password, salt);

    // updating the password using user id
    await User.findByIdAndUpdate(req.user._id, {
        $set: {
            password: newHashPassword
        }
    })


    return res.status(200).send({ "status": "success", "message": "Password changed successfully!!" });
}

export const loggedUser = async (req, res) => {
    return res.status(200).send({ "user": req.user });
}

export const sendResetPasswordEmail = async (req, res) =>{
    const {email} = req.body;
    if(!email){
        return res.status(400).send({"status": "failed", "message": "Email field is required."});
    }

    const user = await User.findOne({email: email});
    if(!user){
        return res.status(400).send({ "status": "failed", "message": "Email doesn't exist." });
    }
} 

