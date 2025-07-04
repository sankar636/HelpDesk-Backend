import AsyncHandler from '../Utils/AsyncHandler.js';
import ApiError from '../Utils/ApiError.js';
import { User } from '../Models/User.model.js';
import { ApiResponse } from '../Utils/ApiResponse.js';
import jwt from "jsonwebtoken";

// Utility: Generate access and refresh tokens
const generateAccessAndRefreshToken = async (userId) => {
    const user = await User.findById(userId);
    if (!user) throw new ApiError(404, "User not found");

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
};

// REGISTER
const registerUser = AsyncHandler(async (req, res) => {
    const { name, email, password, role } = req.body;

    for (const [key, value] of Object.entries({ name, email, password, role })) {
        if (!value?.trim()) throw new ApiError(400, `${key} is required`);
    }

    const existedUser = await User.findOne({
        $or: [{ name: name.toLowerCase() }, { email }],
    });
    if (existedUser) {
        throw new ApiError(409, "User with name or email already exists");
    }

    const user = await User.create({
        name: name.toLowerCase(),
        email,
        password,
        role,
    });

    const createdUser = await User.findById(user._id).select("-password -refreshToken");
    return res.status(201).json(new ApiResponse(201, createdUser, "User registered successfully"));
});

// LOGIN
const loginUser = AsyncHandler(async (req, res) => {
    const { email, name, password } = req.body;

    if (!email && !name) throw new ApiError(400, "Enter email or username");

    const user = await User.findOne({
        $or: [{ name: name?.toLowerCase() }, { email }],
    });

    if (!user) throw new ApiError(401, "User does not exist");

    const isPasswordValid = await user.isPasswordCorrect(password);
    if (!isPasswordValid) throw new ApiError(401, "Invalid credentials");

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id);
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    const options = {
        httpOnly: true,
        secure: true,
    };

    return res.status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(200, {
                user: loggedInUser,
                accessToken,
                refreshToken,
            }, "User logged in successfully")
        );
});

// LOGOUT
const logoutUser = AsyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(req.user._id, {
        $unset: { refreshToken: 1 },
    }, { new: true });

    const options = { httpOnly: true, secure: true };

    return res.status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged out successfully"));
});

// REFRESH TOKEN
const refreshAccessToken = AsyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies?.refreshToken || req.body.refreshToken;

    if (!incomingRefreshToken) throw new ApiError(401, "Unauthorized request");

    const decoded = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded._id);

    if (!user || user.refreshToken !== incomingRefreshToken) {
        throw new ApiError(401, "Invalid or expired refresh token");
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id);
    const options = { httpOnly: true, secure: true };

    return res.status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(200, { accessToken, refreshToken }, "Access token refreshed")
        );
});

const changeCurrentPassword = AsyncHandler(async (req, res) => {

    const { oldPassword, newPassword } = req.body

    if (!oldPassword || !newPassword) {
        throw new ApiError(401, "Password field should not be empth")
    }

    const user = await User.findById(req.user?._id) 

    const isPassword = await user.isPasswordCorrect(oldPassword)

    if (!isPassword) {
        throw new ApiError(400, "Incorrect Password Entered")
    }

    user.password = newPassword 

    await user.save({ validateBeforeSave: false })

    return res.status(200)
        .json(
            new ApiResponse(
                200,
                {},
                "Password changed successfully"
            )
        )
})

// UPDATE ACCOUNT DETAILS WITH PASSWORD
const updateAccountWithPassword = AsyncHandler(async (req, res) => {
    const { name, email, currentPassword, newPassword, confirmPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmPassword) {
        throw new ApiError(400, "All password fields are required");
    }

    const user = await User.findById(req.user._id);
    if (!user) throw new ApiError(404, "User not found");

    const isPasswordValid = await user.isPasswordCorrect(currentPassword);
    if (!isPasswordValid) {
        throw new ApiError(401, "Current password is incorrect");
    }

    if (newPassword !== confirmPassword) {
        throw new ApiError(400, "New password and confirm password do not match");
    }

    user.password = newPassword;
    if (name) user.name = name;
    if (email) user.email = email;

    await user.save();

    return res.status(200).json(
        new ApiResponse(200, null, "Account updated successfully")
    );
});


const getUserProfile = AsyncHandler(async (req, res) => {
  const user = req.user;

  if (!user) {
    throw new ApiError(401, "User not found");
  }

  return res.status(200).json(user);
});

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    updateAccountWithPassword,
    changeCurrentPassword,
    getUserProfile
};