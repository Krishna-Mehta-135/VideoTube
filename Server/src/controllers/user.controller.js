import {User} from "../models/user.model.js";
import {asyncHandler} from "../utils/asyncHandler.js";
import {registerUserSchema} from "../validation/user.validation.js";
import {ApiError} from "../utils/ApiError.js";
import {uploadOnCloudinary} from "../utils/cloudinary.js";
import {ApiResponse} from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({validateBeforeSave: false});

        return {accessToken, refreshToken};
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generationg tokens");
    }
};

const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend
    const {fullName, email, username, password} = req.body;

    // validation - not empty and zod
    const validationResult = registerUserSchema.safeParse(req.body);
    if (!validationResult.success) {
        return res.status(400).json({errors: validationResult.error.issues});
    }

    // check if user already exists
    const existingUser = await User.findOne({
        $or: [{username}, {email}],
    });
    if (existingUser) {
        throw new ApiError(409, "Email or username already exists");
    }

    // check for images,avatar
    const avatarLocalPath = req.files?.avatar?.[0]?.path;

    // Check if coverImage is provided
    let coverImageLocalPath = null;
    if (req.files?.coverImage?.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path;
    }

    // Ensure avatar file is provided
    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required");
    }

    // upload them for cloudinary, avatar
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) {
        throw new ApiError(400, "Failed to upload avatar");
    }

    // create user object - create entry in db
    const user = await User.create({
        fullName,
        username: username.toLowerCase(),
        password,
        email,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
    });

    // remove password and reresh token field from response
    // check for user creation
    const createduser = await User.findById(user._id).select("-password -refreshToken");

    if (!createduser) {
        throw new ApiError(500, "Something went wrong while registring the user");
    }

    // return res
    return res.status(201).json(new ApiResponse(200, createduser, "User registered sucessfully"));
});

const loginUser = asyncHandler(async (req, res) => {
    // req.body  -> data

    const {email, username, password} = req.body;
    //if username or email arent provided

    if (!(username || email)) {
        throw new ApiError(400, "username or email  are required to login");
    }
    // find user
    const user = await User.findOne({
        $or: [{username}, {email}],
    });

    if (!user) {
        throw new ApiError(404, "User doesn't exist");
    }
    //password check
    const isPasswordValid = await user.isPasswordCorrect(password);
    if (!isPasswordValid) {
        throw new ApiError(404, "Password is incorrect");
    }
    //access and refresh token
    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id);

    //send secure cookies
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");
    //we define options to send cookies. if httpOnly is true the cookies would only be intercepted on the server. It increases the security.
    const options = {
        httpOnly: true,
        secure: true,
    };

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {
                user: loggedInUser,
                accessToken,
                refreshToken,
            },
            "User logged in successfully"
        )
    );
});

const logoutUser = asyncHandler(async (req, res) => {
    //got the req.user._id from auth middleware
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined,
            },
        },
        {
            new: true,
        }
    );

    const options = {
        httpOnly: true,
        secure: true,
    };

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out successfully"));
});

//Generate new refresh Token
const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if (!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorized Request: Refresh Token Missing");
    }

    try {
        // Verify the incoming refresh token
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);

        const user = await User.findById(decodedToken?._id);
        if (!user) {
            throw new ApiError(401, "Invalid Refresh Token: User not found");
        }

        // We checked here if the inncoming token from the user is equal to the token stored in the database
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token expired or used");
        }

        const options = {
            httpOnly: true,
            secure: true,
        };

        //Generate new access and refresh tokens for the user
        const {accessToken, refreshToken: newRefreshToken} = await generateAccessAndRefreshTokens(user._id);

        // Update the user's refresh token
        user.refreshToken = newRefreshToken;
        await user.save();

        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json({
            success: true,
            message: "Access Token Refreshed",
            accessToken,
            refreshToken: newRefreshToken,
        });
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token");
    }
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
    const {oldPassword, newPassword} = req.body;

    const user = await User.findById(req.user?._id);
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

    if (!isPasswordCorrect) {
        throw new ApiError(400, "Incorrect Password");
    }

    user.password = newPassword;
    await user.save({validateBeforeSave: false});

    return res.status(200).json(new ApiResponse(200, {}, "Password changed successfully"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
    return res.status(200).json(new ApiResponse(200, req.user, "current user fetched successfully"));
});

const updateUserDetails = asyncHandler(async (req, res) => {
    const {newFullName, newEmail} = req.body;
    if (!newFullName || !newEmail) {
        throw new ApiError(400, "All fields are required");
    }
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName: newFullName,
                email: newEmail,
            },
        },
        {
            new: true,
        }
    ).select("-password");

    return res.status(200).json(200, user, "User details updated successfully");
});

const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.file?.path;

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing");
    }

    // Fetch the user first
    const user = await User.findById(req.user?._id);
    if (!user) {
        throw new ApiError(404, "User not found");
    }

    // Delete the old avatar if it exists
    if (user.avatar) {
        const oldAvatarPublicId = extractPublicIdFromUrl(user.avatar); // Assuming you have a utility function for this
        await cloudinary.uploader.destroy(oldAvatarPublicId);
    }

    // Upload the new avatar
    const avatar = await uploadOnCloudinary(avatarLocalPath);

    if (!avatar.url) {
        throw new ApiError(400, "Error while uploading the avatar");
    }

    // Update the user's avatar in the database
    user.avatar = avatar.url;
    await user.save();

    // Exclude sensitive fields in the response
    const updatedUser = user.toObject();
    delete updatedUser.password;

    return res.status(200).json(new ApiResponse(200, updatedUser, "Avatar updated successfully"));
});

const updateUserCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = req.file?.path;

    if (!coverImageLocalPath) {
        throw new ApiError(400, "Cover Image is missing");
    }

    const user = await User.findById(req.user?._id);

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    if (user.coverImage) {
        // Assuming the cover image URL follows the Cloudinary URL format
        const publicId = user.coverImage.split("/").slice(-2, -1).join("/");
        await cloudinary.uploader.destroy(publicId); // Delete old cover image
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!coverImage.url) {
        throw new ApiError(400, "Error while uploading the cover image");
    }

    const updatedUser = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage: coverImage.url,
            },
        },
        {new: true}
    ).select("-password");

    return res.status(200).json(new ApiResponse(200, updatedUser, "Cover Image updated successfully"));
});

const getUserChannelProfile = asyncHandler(async (req,res) => {
    const {username} = req.params;

    if(!username?.trim()){
        throw new ApiError(400, "Channel name not found.")
    }

    const channel = await User.aggregate([
        {
            $match: {
                username: username?.toLowerCase()
            }
        },
        {
            $lookup:{
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as : "subscribers"
            }
        },
        {
            $lookup:{
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as : "subscribedTo"
            }
        },
        {
            $addFields:{
                subscribersCount: {
                    $size: "subscribers"
                },
                channelsSubscribedToCount: {
                    $size: "$subscribedTo"
                },
                isSubscribed: {
                    $cond: {
                        if: {$in: [req.user?._id, "$subscribers.subscriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: {
                fullName: 1,
                username: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                email: 1
            }
        }
    ])

    if(!channel?.length){
        throw new ApiError(404, "Channel does not exist")
    }

    return res
    .status(200)
    .json(
        new ApiResponse(200, channel[0], "User channel fetched successfully")
    )
})


export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateUserDetails,
    updateUserCoverImage,
    updateUserAvatar,
    getUserChannelProfile,
};
