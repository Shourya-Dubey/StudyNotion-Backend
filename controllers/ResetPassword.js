const User = require("../models/User");
const mailSender = require("../utils/mailSender");
const bcrypt = require("bcrypt");
const crypto = require("crypto");


//resetPasswordToken
exports.resetPasswordToken = async(req, res) => {
    try{
      //get email from body
      const email = req.body.email;

      //check user for this email, email validation
      const user = await User.findOne({ email: email });
      if (!user) {
        return res.json({
          success: false,
          message: `This Email: ${email} is not Registered with us Enter a valid Email`,
        });
      }

      //generate token
      const token = crypto.randomBytes(20).toString("hex")

      //update user by adding token and expiration time
      const updateDetails = await User.findOneAndUpdate(
        { email: email },
        {
          token: token,
          resetPasswordExpires: Date.now() + 5 * 60 * 1000,
        },
        { new: true }
      )
      console.log("DETAILS", updateDetails);

      //create url
      // const url = `http://localhost:3000/update-password/${token}`;
      const url = `https://studynotion-backend-55x8.onrender.com/api/v1/reset-password/${token}`
      

      //send mail containing url
      await mailSender(
        email,
        "Password Reset Link",
        `password Reset Link: ${url}`
      );

      //return response
      return res.json({
        success: true,
        message:
          "Email sent successfully , please check email and change password",
      });
    }catch(error){
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "Something went wrong while sending reset password mail"
        })
    }
    
}


//resetPassword
exports.resetPassword = async(req, res)=>{
    try{
        //data fetch
        const {password, confirmPassword, token} = req.body;

        //validation
        if(password !== confirmPassword){
            return res.json({
                success: false,
                message: "Password not matching"
            })
        }

        //get user detail from db using token
        const userDetails = await User.findOne({token: token});

        //if no entry - invalid token
        if (!userDetails) {
        return res.json({
            success: false,
            message: "Token is invalid",
        });
        }

        //toke time check
        if(!(userDetails.resetPasswordExpires > Date.now())){
            return res.status(403).json({
                success: false,
                message: "Token is expired, please regenerate your token"
            });
        }

        //hash password
        const encryptedPassword = await bcrypt.hash(password, 10);

        //update password
        await User.findOneAndUpdate({token: token}, {password: encryptedPassword}, {new:true});

        //return response
        return res.status(200).json({
            success: true,
            message: "Password reset successful",
        });


    }catch(error){
       return res.json({
        error: error.message,
        success: false,
        message: `Some Error is updating the Password`
       })
    }
}