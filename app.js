const express               =  require('express'),
      expSession            =  require("express-session"),
      app                   =  express(),
      mongoose              =  require("mongoose"),
      passport              =  require("passport"),
      bodyParser            =  require("body-parser"),
      LocalStrategy         =  require("passport-local"),
      passportLocalMongoose =  require("passport-local-mongoose"),
      User                  =  require("./models/user"),
      mongoSanitize = require('express-mongo-sanitize'),
      helmet = require("helmet");
      rateLimit = require('express-rate-limit');
   

app.use(helmet());
//Connecting database
mongoose.set('strictQuery', false);

mongoose.connect("mongodb://localhost/auth_demo");

app.use(expSession({
    secret:"mysecret",       //decode or encode session
    resave: false,          
    saveUninitialized:false,
    cookie:{
        httpOnly: true,
        secure: false,
        maxAge: 1 * 60 * 1000 // 10 minutes
    }
}))

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
passport.use(new LocalStrategy(User.authenticate()));

//=======================
//      O W A S P
//=======================

app.set("view engine","ejs");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

app.use(mongoSanitize({
    replaceWith: '_'
}));

app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

// Prevent Brute Force & DOS Attacks - Rate Limiting

const limit = rateLimit({
    max: 100, // max requests
    windowMs: 60 * 60 * 1000, // 1 Hour of 'ban' / lockout
    message: 'Too many requests' // message to send
});

app.use(limit);

app.use(express.json({ limit: '10kb'})); //body limit is 10


//=======================
//      R O U T E S
//=======================
app.get("/", (req,res) =>{
    res.render("home");
})
function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/login");
}

app.get("/userprofile", isLoggedIn, (req,res) =>{
    res.render("userprofile");
});

//validation helper

function validateUsername(username) {
    const regex = /^[a-zA-Z0-9_]{3,20}$/;
    return regex.test(username);
}

function validatePassword(password) {
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
    return regex.test(password);
};

//Auth Routes
app.get("/login",(req,res)=>{
    res.render("login");
});
app.post("/login",passport.authenticate("local",{
    successRedirect:"/userprofile",
    failureRedirect:"/login"
}),function (req, res){
});
app.get("/register",(req,res)=>{
    res.render("register");
});

app.post("/register", async (req, res) => {
    const { username, password, email, phone } = req.body;

    let errors = [];

    // Username validation
    if (!validateUsername(username)) {
        errors.push("Username must be 3–20 characters (letters, numbers, underscore only).");
    }

    // Password validation
    if (!validatePassword(password)) {
        errors.push("Password must be at least 8 characters and include uppercase, lowercase, number, and special character.");
    }

    if (errors.length > 0) {
        return res.render("register", { errors });
    }

    try {
        const user = new User({
            username,
            email,
            phone
        });

        await User.register(user, password);
        res.redirect("/login");

    } catch (err) {
        console.log(err);

        let errors = [];

        if (err.name === "UserExistsError") {
            errors.push("Username already exists.");
            return res.render("register", { errors });
        }

        errors.push("Registration failed.");
        res.render("register", { errors });
    }
});

app.get("/logout", (req, res, next) => {
    req.logout(function(err) {
        if (err) return next(err);

        req.session.destroy(() => {
            res.clearCookie("connect.sid");
            res.redirect("/");
        });
    });
});

//Listen On Server
app.listen(process.env.PORT || 3000,function (err) {
    if(err){
        console.log(err);
    }else {
        console.log("Server Started At Port 3000");  
    }
});