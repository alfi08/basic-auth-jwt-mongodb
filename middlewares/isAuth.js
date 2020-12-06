const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  const token = req.header("x-auth-token");

  if (!token) return res.status(401).json({ msg: "unatuhorization" });

  try {
    const decoded = jwt.verify(token, "rahasia");
    console.log("decoded ==>", decoded);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(400).json({ msg: "invalid token" });
  }
};
