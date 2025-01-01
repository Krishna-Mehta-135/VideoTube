import { User } from "../models/user.model.js";
import {asyncHandler} from "../utils/asyncHandler.js";
import {registerUserSchema} from "../validation/user.validation.js";
import { ApiError } from "../utils/ApiError.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js"

const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend
    const {fullName, email, username, password} = req.body;
    console.log("email: ", email);

    // validation - not empty and zod
    const validationResult = registerUserSchema.safeParse(req.body);
    if (!validationResult.success) {
        return res.status(400).json({errors: validationResult.error.issues});
    }


    // check if user already exists
    const existingUser = User.findOne({
        $or: [{ username } , { email }]
    })
    if (existingUser){
        throw new ApiError(409, "Email or username already exists")
    }


    // check for images,avatar
    const avatarLocalPath = req.files?.avatar[0]?.path
    console.log(avatarLocalPath);
    
    const coverImageLocalPath = req.files?.coverImage[0]?.path
    console.log(coverImageLocalPath);

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar File is required")
    }


    // upload them for cloudinary, avatar
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400, "Avatar File is required")
    }


    // create user object - create entry in db
    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        username: username.toLowerCase()
    });


    // remove password and reresh token field from response
    // check for user creation
    const createduser = await User.findById(user._id).select("-password -refreshToken")

    if ( !createduser ){
        throw new ApiError(500, "Something went wrong while registring the user")
    }


    // return res
    return res.status(201),json(
        new ApiResponse(200, createduser, "User registered sucessfully")
    )

});

export {registerUser};
