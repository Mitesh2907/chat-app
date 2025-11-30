import jwt from 'jsonwebtoken';
import User from '../models/User.js';

// Middleware to protect routes
export const protectRoute = async (req, res, next) => {
    try {
       
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ success: false, message: "jwt must be provided" });
        }

        const token = authHeader.split(" ")[1]; // "Bearer <token>"

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // User find
        const user = await User.findById(decoded.userID).select("-password");
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        req.user = user;
        next();
    } catch (error) {
        console.log(error.message);
        res.status(401).json({ success: false, message: "Invalid token" });
    }
};
