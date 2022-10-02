//jshint esversion:6

require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");

const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const { use } = require("passport");
const FacebookStrategy = require("passport-facebook").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;

const app = express();

app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

//cookie session

app.use(
  session({
    secret: process.env.COOKIE_SECRETS,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());

app.use(passport.session());

mongoose.connect(
  "process.env.CRED"
);

//MONGODB Schema Define

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose); //Plugin use to hash the database and provides encryption comes with passport.
userSchema.plugin(findOrCreate); //Plugin use to use find or create.

//MONGODB Model Define

const Users = new mongoose.model("Users", userSchema);

passport.use(Users.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  Users.findById(id, function (err, user) {
    done(err, user);
  });
});

app.get("/", function (req, res) {
  res.render("home");
});

//Secrets Page
app.get("/secrets", function (req, res) {
  if (req.isAuthenticated()) {
    Users.find({ secret: { $ne: null } }, function (err, userFound) {
      if (err) {
        console.log(err);
      } else {
        if (userFound) {
          res.render("secrets", { usersWithSecrets: userFound });
        }
      }
    });
  } else {
    res.redirect("/authenticate");
  }
});

//Authenticate Page
app.get("/authenticate", function (req, res) {
  res.render("authenticate");
});

//Analytics Page
app.get("/analytics", function (req, res) {
  const userDB = Users.find();

  const userSecretDB = Users.find(users.secret);

  userDB.count(function (err, count) {
    if (err) console.log(err);
    else {
      res.render("analytics", { registeredUser: count });
    }
  });
});

//Login User

app.post("/login", function (req, res) {
  const user = new Users({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

//Register User

app.post("/register", function (req, res) {
  Users.register(
    { username: req.body.username },
    req.body.password,
    function (err, users) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

//Submit

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/authenticate");
  }
});

app.post("/submit", function (req, res) {
  const receivedSecret = req.body.secret;

  Users.findById(req.user.id, function (err, userFound) {
    if (err) {
      console.log(err);
    } else {
      if (userFound) {
        userFound.secret = receivedSecret;
        userFound.save(function () {
          res.redirect("/secrets");
        });
      }
    }
  });
});

//Google Auth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      Users.findOrCreate(
        { googleId: profile.id, googleName: profile.displayName },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

//Google Auth
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/:userID", function (req, res) {
  const requesteduserID = req.params.userID;
  Users.findOne({ _id: requesteduserID }, function (err, user) {
    const userSecret = user.secret;
    res.render("user", { secret: userSecret });
  });
});

app.listen(process.env.PORT || 3000, function () {
  console.log(
    "Server listening on port %d in %s mode",
    this.address().port,
    app.settings.env
  );
});
