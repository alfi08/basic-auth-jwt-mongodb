const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const isAuth = require("./middlewares/isAuth");

const app = express();
const port = 5000;

// model
const User = require("./models/User");
const { token } = require("morgan");

// connect db
mongoose
  .connect("mongodb://localhost/basic-auth", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then((success) => {
    console.log("mongodb connected");
    app.listen(port, console.log(`server running on port ${[port]}`));
  })
  .catch((err) => console.log(err));

// middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(morgan("dev"));

app.get("/", (req, res) => {
  res.json({ message: "Hello 😁😁" });
});

// auto login
app.get("/auto-login", isAuth, (req, res) => {
  User.findById(req.user.id)
    .select("-password")
    .then((doc) => {
      res.json(doc);
    });
});

// login
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  console.log("==>", req.body);

  if (!email || !password) {
    return res.status(400).json({ msg: "failed!" });
  }

  User.findOne({ email: email }).then((doc) => {
    if (!doc)
      return res.status(400).json({ msg: "email or password is invalid" });

    console.log(`doc => ${doc}| password : ${password}`);
    bcrypt.compare(password, doc.password).then((isPasswordMatch) => {
      if (isPasswordMatch) {
        jwt.sign({ id: doc._id }, "rahasia", (err, token) => {
          if (err) throw err;
          res.json({
            msg: "login success ",
            user: { email: doc.email, id: doc._id },
            token,
          });
        });
      } else {
        res.status(400).json({ msg: "email or password is invalid" });
      }
    });
  });
});

// register
app.post("/register", (req, res) => {
  const { email, password } = req.body;

  console.log("==>", req.body);

  if (!email || !password) {
    return res.status(400).json({ msg: "failed!" });
  }

  bcrypt.genSalt(10, (err, salt) => {
    if (err) throw err;

    // cek user
    User.findOne({ email: email }).then((doc) => {
      // cek jika email udah terdaftar
      if (doc)
        return res.status(400).json({ message: "email is already exist" });

      // hash password
      bcrypt.hash(password, salt, (err, passHash) => {
        if (err) throw err;

        new User({
          email: email,
          password: passHash,
        })
          .save()
          .then((doc) => {
            jwt.sign({ id: doc._id }, "rahasia", (err, token) => {
              res.json({ message: "register success ", id: doc._id, token });
            });
          })
          .catch((err) => console.log(err));
      });
    });
  });
});
