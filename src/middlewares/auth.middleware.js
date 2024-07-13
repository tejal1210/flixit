import JWT from 'jsonwebtoken';
import asyncHandler from '../utils/asyncHandler.js';
import ApiError from '../utils/ApiError.js';
import { User } from '../models/user.model.js';

// Middleware to verify JWT
export const verifyJWT = asyncHandler(async (req, _, next) => {
    try {
        // Extract the access token from cookies or the Authorization header
        const accessToken = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");

        // If no access token is provided, throw an unauthorized error
        if (!accessToken) {
            throw new ApiError(401, "Unauthorized request");
        }

        // Verify the access token using the secret key
        const decodedToken = JWT.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);

        // Find the user associated with the decoded token, excluding password and refreshToken fields
        const user = await User.findById(decodedToken?._id).select(" -password -refreshToken");

        // If no user is found, throw an invalid token error
        if (!user) {
            throw new ApiError(401, "Invalid access token");
        }

        // Attach the user to the request object for further use in the request lifecycle
        req.user = user;
        next();
    } catch (error) {
        // Handle any errors during token verification and user fetching
        throw new ApiError(401, error?.message || "Invalid access token");
    }
});
