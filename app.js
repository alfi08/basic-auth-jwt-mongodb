const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const morgan = require("morgan");

const app = express();
const port = 5000;

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

const usersRoute = require("./routes/usersRoute");
app.use("/api/users", usersRoute);
