const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const nodemailer = require('nodemailer');
const cloudinary = require('cloudinary').v2;
const frontendUrl = process.env.FRONTEND_URI || "http://localhost:3000";

//@desc Get all Users
//@route Get /api/users
//@access public
const getUsers = asyncHandler(async (req, res) => {
  const apiKey = req.headers.authorization;
  if (apiKey !== `Bearer ${process.env.API_KEY}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const users = await User.find();

  res.status(200).json(users);
});

// @desc get Users
// @route GET /api/users/:id
// @access public
const getUser = asyncHandler(async (req, res) => {
  const apiKey = req.headers.authorization;
  if (apiKey !== `Bearer ${process.env.API_KEY}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const user = await User.findById(req.params.id);
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  res.status(200).json(user);
});

//@desc update Users
//@route PUT /api/users/:id
//@access public
const updateUser = asyncHandler(async (req, res) => {
  const apiKey = req.headers.authorization;
  if (apiKey !== `Bearer ${process.env.API_KEY}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const user = await User.findById(req.params.id);
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  const updatedUser = await User.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });

  res.status(200).json(updatedUser);
});

//@desc Register a user
//@route POST /api/users/register
//@access public
const registerUser = asyncHandler(async (req, res) => {
  const apiKey = req.headers.authorization;
  if (apiKey !== `Bearer ${process.env.API_KEY}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  try {
    const {
      username,
      dob,
      gender,
      email,
      address,
      city,
      pincode,
      password,
      bio
    } = req.body;

    // Check if the user is already registered
    const userAvailable = await User.findOne({ email });
    if (userAvailable) {
      return res.status(400).json({ error: "User already registered!" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Hashed Password: ", hashedPassword);

    // Create the user
    const user = await User.create({
      username,
      dob,
      gender,
      email,
      address,
      city,
      pincode,
      password: hashedPassword,
      bio
    });

    const accessToken = jwt.sign(
      {
        user: {
          id: user.id,
          username: user.username,
          dob: user.dob,
          gender: user.gender,
          email: user.email,
          address: user.address,
          city: user.city,
          pincode: user.pincode,
          bio: user.bio
        },
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "1d" }
    );

    // Send a success response
    return res
      .status(200)
      .json({ message: "User registered successfully", user, accessToken });
  } catch (error) {
    // Handle any errors that occur during registration
    console.error("Error:", error);
    return res.status(500).json({ error: "Registration failed" });
  }
});

//@desc Login user
//@route POST /api/users/login
//@access public
const loginUser = asyncHandler(async (req, res) => {
  const apiKey = req.headers.authorization;
  if (apiKey !== `Bearer ${process.env.API_KEY}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      res.status(400);
      throw new Error("All fields are mandatory!");
    }
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      const accessToken = jwt.sign(
        {
          user: {
            id: user.id,
            username: user.username,
            dob: user.dob,
            gender: user.gender,
            email: user.email,
            address: user.address,
            city: user.city,
            pincode: user.pincode,
            bio: user.bio
          },
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "1d" }
      );
      res.status(200).json({ accessToken });
    } else {
      res.status(401);
      throw new Error("Email or password is not valid");
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const updateUserImage = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const result = await cloudinary.uploader.upload(
      `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`,
      {
        folder: 'user_profile_images', 
      }
    );

    user.userImage = result.secure_url;
    await user.save();

    res.status(200).json({ userImage: user.userImage });
  } catch (error) {
    console.error('Error uploading image:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc Forgot Password
// @route POST /api/users/forgot-password
// @access public
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  const resetToken = jwt.sign(
    { id: user._id },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: '1h' }
  );

  const encodedToken = encodeURIComponent(resetToken);
  const resetUrl = `${frontendUrl}/reset-password?token=${encodedToken}`;
  
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: 'Reset Password for Nexus',
    text: `You requested a password reset for your Nexus account. Please click on the following link to reset your password: ${resetUrl}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      return res.status(500).json({ message: 'Email could not be sent' });
    }
    res.status(200).json({ message: 'Password reset email sent' });
  });
});

// @desc Reset Password
// @route POST /api/users/reset-password/:token
// @access public
const resetPassword = asyncHandler(async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    res.status(400).json({ message: 'Invalid or expired token' });
  }
});

module.exports = {
  registerUser,
  loginUser,
  getUsers,
  getUser,
  updateUser,
  forgotPassword,
  resetPassword,
  updateUserImage
};
