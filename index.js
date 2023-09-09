const express = require("express");
const mongoose = require("mongoose");
const app = express();
const userDb = require("./user");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const saltRounds = 10;

mongoose
  .connect("mongodb+srv://vaibhav:vaibhav1234@cluster0.xfaokel.mongodb.net/")
  .then(async () => {
    console.log("connected to mongodb");
  })
  .catch((error) => console.error(error));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.post("/", (req, res, next) => {
  req.status(200).send("hello");
  console.log("hello");
});

app.post("/login", async (req, res, next) => {
  try {
    const { password, username } = req.body;
    const existingUser = await userDb.findOne({ username }).lean();
    if (!existingUser) {
      return res.status(401).json({ message: "User does not exist" });
    }
    let isMatch;
    try {
      isMatch = await bcrypt.compare(password, existingUser.password);
    } catch (error) {
      res.json({
        message: "Something went wrong",
      });
    }

    if (isMatch) {
      const payload = {
        ...existingUser,
      };
      jwt.sign(
        payload,
        "qwertyuiopqwertyuiopqwertyuiopqwertyuiop",
        { expiresIn: 7 * 24 * 3600 },
        (err, token) => {
          if (err) console.error({ message: "There is some error in token" });
          else {
            return res.json({
              success: true,
              token: `Bearer ${token}`,
            });
          }
        }
      );
    } else {
      return res.status(401).json({ message: "Incorrect Password" });
    }
  } catch (error) {
    return res.status(401).json({ message: "Something Went Wrong" });
  }
});

app.post("/signup", async (req, res, next) => {
  try {
    const { email, password, username, phonenumber } = req.body;
    if (!email || !password || !username || !phonenumber) {
      return res.status(401).json({ message: "missing Credentials" });
    }
    let existingUser;
    try {
      existingUser = await userDb
        .findOne({ username, email, phonenumber })
        .lean();
    } catch (error) {
      return res.status(401).json({ message: "Something Went Wrong" });
    }

    if (existingUser) {
      res.status(400).send({ error: "User already exists" });
    }
    bcrypt.genSalt(saltRounds, function (err, salt) {
      bcrypt.hash(password, salt, async function (err, hash) {
        if (err) throw err;
        const payload = {
          email,
          password: hash,
          username,
          phonenumber,
        };

        const newUser = await userDb.create({ ...payload });
        console.log(newUser);
        const userPayload = {
          ...newUser,
        };
        jwt.sign(
          userPayload,
          "qwertyuiopqwertyuiopqwertyuiopqwertyuiop",
          { expiresIn: 7 * 24 * 3600 },
          (err, token) => {
            if (err) console.error({ message: "There is some error in token" });
            else {
              return res.json({
                success: true,
                token: `Bearer ${token}`,
              });
            }
          }
        );
      });
    });
  } catch (error) {
    return res.status(401).json({ message: "Something Went Wrong" });
  }
});

app.post("/reset-password", async (req, res, next) => {
  try {
    const { email, password, username, newPassword } = req.body;

    let existingUser;
    try {
      existingUser = await userDb.findOne({ username, email }).lean();
      if (!existingUser)
        return res.status(400).send({ message: "No User Exists" });
    } catch (error) {
      console.error(error);
      res.status(400).send({ message: "Something went wrong" });
    }

    let isMatch;
    try {
      isMatch = await bcrypt.compare(password, existingUser.password);
    } catch (error) {
      res.json({
        error: "Something went wrong",
      });
    }
    if (!isMatch) {
      return res.status(401).json({ message: "Incorrect Password" });
    }

    bcrypt.genSalt(10, (err, salt) => {
      bcrypt.hash(newPassword, salt, async (err, hash) => {
        if (err) throw err;
        let value;
        try {
          value = await userDb.updateOne(
            { username, email },
            { password: hash }
          );
        } catch (error) {
          return res.status(400).send({ message: "Something went wrong!" });
        }
        res.status(200).send("Success");
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("server Error");
  }
});

app.post("/logout", async (req, res, next) => {
  try {
    const { token } = req.body;
    const tokenized = token?.split(" ")[1];
    const decode = jwt.verify(
      tokenized,
      "qwertyuiopqwertyuiopqwertyuiopqwertyuiop"
    );
    if (decode) {
      res.json({
        success: true,
        data: decode,
      });
    } else {
      res.json({
        message: "Not Authorized",
        data: "error",
      });
    }
  } catch (error) {
    return res.status(401).json({ message: "Invalid Token" });
  }
});

app.listen(5000, () => console.log(`localhost at : ${5000}`));
