import jwt from "jsonwebtoken";
import {ApiError} from "../utils/ApiError";
import {asyncHandler} from "../utils/asyncHandler";
import {User} from "../models/user.model";

export const verifyJWT = asyncHandler(async (req, _, next) => {
//added _ instead of res because res is not used
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");
        // We got the token 

        if (!token) {
            throw new ApiError(401, "Unauthorized request");
        }

        //Verifying the token
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        //Remove password and refresh token from user
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken");

        if (!user) {
            throw new ApiError(401, "Invalid Access Token");
        }

        //Now we will get access to req.user in logout
        req.user = user;
        next();
    } catch (error) {
        throw new ApiError(401, error?.message || "invalid Access Token");
    }
});
