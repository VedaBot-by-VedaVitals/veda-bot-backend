const express = require("express");
const router = express.Router();
const {
  getUsers,
  getUser,
  updateUser,
  registerUser,
  loginUser,
} = require("../controllers/UserControllers");

router.route("/").get(getUsers);
router.route("/:id").get(getUser).put(updateUser);
router.route("/login").post(loginUser);
router.route("/register").post(registerUser);

module.exports = router;
