import express from "express";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import path from "path";
import jwt  from "jsonwebtoken";
import bcrypt from "bcrypt"

const app = express();

mongoose.connect("mongodb://localhost:27017" , {
    dbName:"backend",
}).then(() => {
    console.log("database connected")
}).catch((err) => {
    console.log(err);
})

const userSchema = new mongoose.Schema({
    name: String,
    email : String,
    password : String,
});

const User = mongoose.model("user" , userSchema); 

//use middleware we use "app.use()";
app.use(express.static(path.join(path.resolve() , "public")));
// using middleware for read the content of the post method:
app.use(express.urlencoded({extended: true}));
//using cookie-parse to read cookies in the console so its middleware
app.use(cookieParser());

app.set("view engine" , "ejs");

//authentication : 
const isAuthenticated = async (req,res,next) => {

    const { token } = req.cookies;

    if(token){

        const decoded = jwt.verify(token , "sadfdfadfafaf")

        req.user = await User.findById(decoded._id);

        next();
    }
    else{
        res.redirect("/login");
    }
}

app.get("/" ,isAuthenticated , (req,res) => {
    res.render("logout", { name: req.user.name });
})

//login route
app.get("/login" , (req,res) => {
    res.render("login");
})

//register route
app.get("/register" , (req,res) => {
    res.render("register");
})

//Register post request : 
app.post("/register" , async (req,res) => {
    const { name , email , password } = req.body;
    
    // to check wether the registered user is exist or not
    let user = await User.findOne({email})

    if(user){
        return res.redirect("/login");
    }

    //bcrypt is used to hide the password given by the users : 
    const hashedPassword = await bcrypt.hash(password , 10)

     user = await User.create({
        name,
        email,
        password : hashedPassword,
    })


    //using jwt token to make secure of the user.id
    const token = jwt.sign({_id : user._id} , "sadfdfadfafaf")

    res.cookie("token", token , {
        httpOnly: true,
        expires: new Date(Date.now()+ 60 * 1000)
    })

    res.redirect("/");
})

// login post request:
app.post("/login" , async(req, res) => {

    const {email , password} = req.body;

    let user = await User.findOne({email});

    // if not exist then go to the register : 
    if(!user){
        return res.redirect("/register");
    }

    // else if existed then : 
    // const isMatch = user.password === password;
    const isMatch = await bcrypt.compare(password , user.password);

    if(!isMatch){
        return res.render("login" , { email , message : "Incorrect Password"});
    }

    const token = jwt.sign({_id : user._id} , "sadfdfadfafaf")

    res.cookie("token", token , {
        httpOnly: true,
        expires: new Date(Date.now() + 60 * 1000)
    })

    res.redirect("/");
})

//logout route
app.get("/logout" , (req,res) => {
    res.cookie("token", "null",{
        httpOnly:true,
        expires: new Date(Date.now())
    })

    res.redirect("/")
})

app.listen(3000 , () => {
    console.log("server is working");
})