require("dotenv").config();

const http           = require("http");
const express        = require("express");
const session        = require("express-session");
const MySQLStore     = require("express-mysql-session")(session);
const passport       = require("passport");
const fs             = require("fs");
const GoogleStrategy = require("passport-google-oauth2").Strategy;

const app = express();
const server = http.createServer(app);
const PORT = 8080;

const GOOGLE_CLIENT_ID     = process.env.CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.CLIENT_SECRET;

const options = {
    host:     "localhost",
    port:     3306,
    user:     "root",
    password: "root",
    database: "session_test",
};

const sessionStore = new MySQLStore(options);

app.use(
    session({
        secret: "secret key",
        store: sessionStore,
        resave: false,
        saveUninitialized: false,
    })
);

app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    done(null, id);
});

passport.use(
    new GoogleStrategy(
        {
            clientID: GOOGLE_CLIENT_ID,
            clientSecret: GOOGLE_CLIENT_SECRET,
            callbackURL: "http://127.0.0.1:8080/auth/google/callback",
            passReqToCallback: true,
        },
        function (request, accessToken, refreshToken, profile, done) {
            console.log(profile);
            console.log(accessToken);

            return done(null, profile);
        }
    )
);

app.get("/login", (req, res) => {
    if (req.user) return res.redirect("/");
    fs.readFile("./webpage/login.html", (error, data) => {
        if (error) {
            console.log(error);
            return res.sendStatus(500);
        }

        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(data);
    });
});

app.get("/", (req, res) => {
    if (!req.user) return res.redirect("/login");
    fs.readFile("./webpage/main.html", (error, data) => {
        if (error) {
            console.log(error);
            return res.sendStatus(500);
        }

        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(data);
    });
});

app.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["email", "profile"] })
);

app.get(
    "/auth/google/callback",
    passport.authenticate("google", {
        successRedirect: "/",
        failureRedirect: "/login",
    })
);

app.get('/logout', function(req, res, next) {
    req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect('/');
    });
  });

server.listen(PORT, () => {
    console.log(`Server running on ${PORT}`);
});