const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const router = express.Router();

const isAuth = require("../middlewares/isAuth");

const User = require("../models/User");

// @PRIVATE GET /users/auto-login => auto login users
router.get("/auto-login", isAuth, async (req, res) => {
  const doc = await User.findById(req.user.id).select("-password");
  res.json(doc);
});

// @PUBLIC POST /users/login=>  login users
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log("==>", req.body);

    if (!email || !password) {
      return res
        .status(400)
        .json({ status: "FAILED", message: "Check Your Fields!" });
    }

    const userData = await User.findOne({ email: email });
    if (!userData)
      return res
        .status(400)
        .json({ status: "FAILED", message: "Email or Password is Invalid" });

    const isPasswordMatch = await bcrypt.compare(password, userData.password);
    if (isPasswordMatch) {
      jwt.sign({ id: userData._id }, "rahasia", (err, token) => {
        if (err) throw err;
        res.json({
          message: "login success ",
          user: { email: userData.email, id: userData._id },
          token,
        });
      });
    } else {
      res.status(400).json({ message: "email or password is invalid" });
    }
  } catch (err) {
    throw err;
  }
});

// @PUBLIC POST /users/register=>  register  users
router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log("==>", req.body);

    if (!email || !password) {
      return res.status(400).json({ message: "failed!" });
    }

    const userData = await User.findOne({ email: email });
    // cek jika email udah terdaftar
    if (userData)
      return res
        .status(400)
        .json({ status: "FAILED", message: "email is already exist" });

    const salt = await bcrypt.genSalt(10);
    console.log("salt =>", salt);

    // hash password
    const passHash = await bcrypt.hash(password, salt);
    console.log("passHash", passHash);
    const newUser = await new User({
      email: email,
      password: passHash,
    }).save();
    jwt.sign({ id: newUser._id }, "rahasia", (err, token) => {
      res.json({ message: "register success ", id: newUser._id, token });
    });
  } catch (err) {
    throw err;
  }
});

module.exports = router;
