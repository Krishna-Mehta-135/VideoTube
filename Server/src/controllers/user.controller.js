import {User} from "../models/user.model.js";
import {asyncHandler} from "../utils/asyncHandler.js";
import {registerUserSchema} from "../validation/user.validation.js";
import {ApiError} from "../utils/ApiError.js";
import {uploadOnCloudinary} from "../utils/cloudinary.js";
import {ApiResponse} from "../utils/ApiResponse.js";


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
    const avatarLocalPath = req.files?.avatar[0]?.path;

    // const coverImageLocalPath = req.files?.coverImage[0]?.path;
    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path;
    }

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar File is required");
    }

    // upload them for cloudinary, avatar
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) {
        throw new ApiError(400, "Avatar File is required");
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
        throw new ApiError(400, "username or email are required");
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
    const {accessToken, refreshToken} = generateAccessAndRefreshTokens(user._id);

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
                refreshToken :undefined
            }
        },
        {
            new: true
        }
    ) 

    const options = {
        httpOnly: true,
        secure: true,
    };

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out successfully"))
});

export {registerUser, loginUser, logoutUser};
