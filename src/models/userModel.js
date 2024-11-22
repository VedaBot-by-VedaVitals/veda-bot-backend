const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true },
    dob: { type: Date, required: true },
    gender: {
      type: String,
      enum: ["Male", "Female"],
    },
    email: { type: String, required: true },
    address: { type: String, required: true },
    city: { type: String, required: true },
    pincode: { type: Number, required: true },
    password: { type: String, required: true },
    userImg: { type: String },
    bio: { type: String },
    role: { type: String, enum: ["user", "admin"], default: "user" }
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("User", userSchema);
