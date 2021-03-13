const User = require('../models/user');
const jwt = require('jsonwebtoken');//used to generate signed token
const expressJwt = require('express-jwt');//uswed for authorization check

const {errorHandler} = require('../helpers/dbErrorHandler')//imports the code for error message from errorHandler

exports.signup =(req,res) => {
   console.log("req.body", req.body);
    const user = new User(req.body);
    user.save((err, user)=>{
        if(err) {
            return res.status(400).json({
                err: errorHandler(err)
            });
        }/**
         * 
         when we create an user in postman , it prints out all the info including the salt and hashed password
         to avoid that we set the value of salt and hashed password to be undefined
         */
        user.salt = undefined;
        user.hashed_password = undefined;
        res.json({
            user 
        })
    })
};

 exports.signin = (req, res) => {
     //find the user based on the email
     const { email, password } = req.body;
     User.findOne({email}, (err, user) => {
         if(err || !user) {
             return res.status(400).json({
                 error: "User with given email doen not exist. Please signup"
             });
         }
         //if user is found , the email and password shoul match
         //password should be in encrypted format
         //create authenticate method in user model
         if(!user.authenticate(password)) {
             return res.status(401).json({
                 error: 'Email and password dont match'
             })
         }

         //generate a signed token with user id and secret
         const token = jwt.sign({_id: user._id }, process.env.JWT_SECRET);
         //persist the token as 't' in cookie with expiry date
         res.cookie("t", token, { expire: new Date() + 9999});//9999 seconds
         // return response with user and token to frontend client
         const { _id, name, email, role}= user;
         return res.json({ token, user: {_id, email, name, role}});
         
     });
 };



 exports.signout = (req, res) => {
     res.clearCookie('t')
     res.json({message: 'Signout success'});
};
//protect the routes 
exports.requireSignin = expressJwt({
    secret: process.env.JWT_SECRET,
    userProperty: 'auth'
});

exports.isAuth= (req, res, next) => {
    let user = req.profile && req.auth && req.profile._id ==req.auth._id;
    if(!user) {
        return res.status(403).json({
            error: "Access Denied"
        });
    }
    next();

};

exports.isAdmin = (req, res, next) => {
    if(req.profile.role === 0 ){
        return res.status(403).json ({
            error: "Admin resource! Access denied"
        });
    }
    next();
};
