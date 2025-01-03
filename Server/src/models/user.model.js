import mongoose, {Schema} from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const userSchema = new Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
            index: true,
            //Index is set ot true beacuse it willl make searching easy and fast. It might be a little exprnsive.
        },

        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            index: true,
        },

        fullName: {
            type: String,
            trim: true,
            index: true,
        },

        avatar: {
            type: String, //cloudinary url
            required: true,
        },

        coverImage: {
            type: String, //cloudinary url
        },

        watchHistory: [
            {
                type: Schema.Types.ObjectId,
                ref: "Video",
            },
        ],

        password: {
            type: String,
            required: true,
        },

        refreshToken: {
            type: String,
        },
    },
    {
        timestamps: true,
    }
);

// this .pre is a hook which in this context carries out the functionbefore saving. We can also do other things.
//  We used an normal function because the ordinary arrow function/callback doesn't have access to the 'this' keyword and wont be able to extract the password from the userSchema
userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();

    this.password = await bcrypt.hash(this.password, 10);
});

// We checked if the encrypted pass is same as password written by user
userSchema.methods.isPasswordCorrect = async function (password) {
    return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function () {
    return jwt.sign(
        {
            _id: this.id,
            email: this.email,
            username: this.username,
            fullName: this.fullName,
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    );
};
userSchema.methods.generateRefreshToken = function () {
    return jwt.sign(
        {
            _id: this.id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    );
};

export const User = mongoose.model("User", userSchema);
