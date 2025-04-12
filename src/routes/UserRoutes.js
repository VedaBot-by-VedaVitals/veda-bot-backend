const express = require("express");
const router = express.Router();
const {
  getUsers,
  getUser,
  updateUser,
  updateUserImage,
  registerUser,
  loginUser,
  forgotPassword,
  resetPassword,
} = require("../controllers/UserControllers");
const multer = require('multer');
const storage = multer.memoryStorage();
const upload = multer({ storage });

router.route("/").get(getUsers);
router.route("/:id").get(getUser).put(updateUser);
router.route("/login").post(loginUser);
router.route("/register").post(registerUser);

router.post('/forgot-password', forgotPassword);
router.post('/reset-password/:token', resetPassword);

router.put('/upload/:id', upload.single('image'), updateUserImage);

module.exports = router;
