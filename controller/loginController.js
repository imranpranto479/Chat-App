const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const User = require("../models/People")
const createError = require("http-errors")
//get login page
function getLogin(req,res, next){
    res.render("index")
}

//do login
const login = async(req,res,next)=>{
    try {

        //find a user who has this email/username
        const user = await User.findOne({
            $or:[{email: req.body.username}, {mobile: req.body.username}]

        })
        
        if(user && user._id){
            const isValidPassword = await bcrypt.compare(
                req.body.password,
                user.password
            )

            if (isValidPassword){
                //preapre the user object to genereate token
                const userObject = {
                    username: user.name,
                    mobile: user.mobile,
                    email: user.email,
                    role: "user"
                }

                //generate token
                const token = jwt.sign(userObject, process.env.JWT_SECRET,{
                    expiresIn: process.env.JWT_EXPIRY,
                  
                })

                //set cookie
                res.cookie(process.env.COOKIE_NAME, token,{
                    maxAge: process.env.JWT_EXPIRY,
                    httpOnly: true,
                    signed: true

                })

                //set logged in user local identidier
                res.locals.loggedInUser =  userObject;
                res.render("inbox");
            }
                else{
                    throw createError("Login failed! Please try again")
                }
            }
    
        else{
            throw createError("Login failed! Please try again")

        }
    } catch (error) {
        res.render("index", {
            data:{
                username: req.body.username
            },
            errors:{
                common:{
                    msg: err.message
                }
            }
        })
    
        
    }
}

// do logout
function logout(req, res) {
    res.clearCookie(process.env.COOKIE_NAME);
    res.send("logged out");
  }
module.exports ={
    getLogin,
    login,
    logout

}