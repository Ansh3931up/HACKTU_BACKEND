import { User } from '../module/user.model.js';
import ApiError from '../utilities/ApiError.js';
import ApiResponse from '../utilities/ApiResponse.js';
import {asyncHandler } from '../utilities/asyncHandler.js'
import { uploadOnCloudinary } from '../utilities/cloudinary.js';
import sendEmail from '../utilities/sendEmail.js';
import crypto from "crypto";

const getAllUsers = asyncHandler(async (req, res) => {
    const users = await User.find({}).select('-posts'); // Assuming 'posts' is analogous to 'lectures' in Blog model
    // const totalUsers = users.length;
    return res
        .status(200)
        .json(new ApiResponse(200, users, "All users present"));
});

const generateAccessandrefershToken=async(userid)=>{
    try {
        const user=await User.findById(userid)
        const accessToken=user.generateAccessToken()
        const refreshToken=user.generateRefreshToken()
        user.refreshToken=refreshToken;
        user.save({ validateBeforeSave:false})

        return {accessToken,refreshToken}


        
    } catch (error) {
        throw new ApiError(500,"unable to generate access and refresh token")
    }
}
const options={
    maxAge:7*24*60*60*1000,

   

    httpOnly:true,

    secure:true,
    sameSite:'None'
}
const register=asyncHandler(async(req,res)=>{
    const {fullname,email,password,State,Pincode,address,role}=req.body;

    if([fullname,email,password,State,Pincode,address].some((item)=>item?.trim()==='')){
        throw new ApiError(404,"data is incomplete");
    }
    const existing=await User.findOne({
        $or:[{email},{fullname}]
    })
    console.log(existing);
    if(existing){
        throw new ApiError(404,"this user already exists")
    }

    console.log(req.file);
    console.log(req.file.path);
    const avatarLocalPath=req.file?.path;//ye req ka extra path files vala multer provide krata ha
    // // const coverImageLocalPath=req.files?.coverImage[0]?.path; 

   
    if(!avatarLocalPath){
    throw new ApiError(400,"avatar path is not found")
    }


    const avatar=await uploadOnCloudinary(avatarLocalPath);
    // // const coverImage= await uploadOnCloudinary(coverImageLocalPath);

    if(!avatar){
    throw new ApiError(400,"avatar is enable to be storaed")
    }

    const user=await User.create({
        fullname,
        avatar:avatar.url,
        email,
        password,
        State,
        Pincode,
        address,
        
        
    })

    const createUser=await User.findById(user._id).select(
    "-password -refreshToken"//id seelect krka password and refreshToken isma sa delete kr diya
    )
    //isa pta chalaga ki user create bi hua ha ki nhi

    if(!createUser){
        throw new ApiError(400,"Something went wrong while registering the user")
    }
    // await user.save();
    // const {accessToken,refreshToken}=await generateAccessandrefershToken(user._id);

    return res
        .status(201)
        .json(new ApiResponse(200,createUser,"User created successfully" )
    //     .cookie("refreshToken",refreshToken,options)
    //     .cookie("accessToken",accessToken,options)
    )

    }) 
const login=asyncHandler(async(req,res)=>{
    const {fullname,email,password}=req.body;
    console.log("yaha dekho",fullname,email,password)
    const user=await User.findOne({
        $or:[{email},{fullname}]
    })
    console.log(user)

    if(!user){
        throw new ApiError(404,"user not found");
    }

    const isPasswordCorrect=await user.verifyPassword(password);
    if(!isPasswordCorrect){
        throw new ApiError(404,"passwored incorrect");
    }
    const {accessToken,refreshToken}=await generateAccessandrefershToken(user._id);
    return res
        .cookie("refreshToken", refreshToken, options)
        .cookie("accessToken", accessToken, options)
        .status(200)
        .json(new ApiResponse(200,user, 'You are logged in'));


    
})

const logout=asyncHandler(async(req,res)=>{

    const user=req.user;
    if(!user){
        throw new ApiError(404,"no user logged in");
    }
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:
            {refreshToken:undefined}
        },{
            new:true
        }

    )
    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(200,{},"user logout "))
})

const getProfile=asyncHandler(async(req,res)=>{
    const user=req.user;
    res
    .status(200)
    .json(new ApiResponse(200,user,"User data"));
})
const forgot=asyncHandler(async(req,res)=>{
    const {email}=req.body;
    const user=await User.findOne({
        email
    })
    if(!user){
        throw new ApiError(400,"User does not exists ");
    }

    const resetToken=await user.generatePasswordResetToken();
    await user.save();
    let ans=process.env.FRONTEND_URL;
    console.log(ans)
    const resetPasswordURL=`${ans}/reset/${resetToken}`;
    console.log(resetPasswordURL);
    try {
        await sendEmail(email,'AASA HI',"heelo jiii");



        res.status(200).json(new ApiResponse(200,`Reset password token has been sent to ${email} successfully`))
        
    } catch (error) {
        user.forgotPasswordExpiry=undefined;
        user.forgotPasswordToken=undefined;
        await user.save();
        console.log(error)
        res.status(500).json(new ApiError(500,"email not send"))
    }
});

const reset=asyncHandler(async(req,res)=>{

    const {password}=req.body;

    const {resetToken}=req.params;

    const forgotPasswordToken=crypto//encrypt krka store krana 
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');


    const user=await User.findOne({
        forgotPasswordToken,
        forgotPasswordExpiry:{$gt:Date.now()}
    })

    if(!user){
        throw new ApiError(404,"user not found or token expired");
    }
    user.password=password;
    user.forgotPasswordToken=undefined;
    user.forgotPasswordExpiry=undefined;

    user.save();
    return res
        .status(400)
        .json( new ApiResponse(200,"successfully changed"));
    

})
const changeCurrentPassword=asyncHandler(async(req,res)=>{
    console.log(req.body)
    const {oldPassword,newPassword}=req.body;
    // if(newPassword!=confPassword){
    //     throw new ApiError(400,"newpassword and confpassword is not same")
    // }

    const user=await User.findById(req.user?._id)
    console.log(user)
    const isPasswordValids=await user.verifyPassword(oldPassword)
    console.log(isPasswordValids)
    if(!isPasswordValids){
        throw new ApiError(401,"unauthorized access wrong password")
    }

    user.password=newPassword
    await user.save({validateBeforeSave:false})// baaki sab same rhta hai

    return res
    .status(200)
    .json(new ApiResponse(200,"password changed successfully"))
})

const getCurrentUser=asyncHandler(async(req,res)=>{
    const user=req.user;
    // console.log(user)
    return res
    .status(200)
    .json(new ApiResponse(200,user,"current user fetched successfully"))
})

const updateAccountDetails=asyncHandler(async(req,res)=>{
    const {fullname,email,Pincode,State,address}=req.body
    console.log(req.body)
    if(!fullname||!email|!Pincode||!State||!address){
        throw new ApiError(404,"all fields are required")
    }
    const newuser= await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:
            {fullname,email,Pincode,State,address}
        },
        {
            new:
            true
        }
    ).select("-password -refreshToken")
    console.log(newuser);
    return res
        .status(200)
        .json(new ApiResponse(200,newuser,"Account details updated successfully"))
})
const calculateTotalRevenue = asyncHandler(async (req, res) => {
    const users = await User.find({}).populate('isSubscribed', 'price');
    let totalRevenue = 0;

    users.forEach(user => {
        user.isSubscribed.forEach(subscription => {
            totalRevenue += parseFloat(subscription.price);
        });
    });

    return res.status(200).json(new ApiResponse(200, totalRevenue, "Total revenue calculated successfully"));
});



// export {register,login,logout,getProfile,forgot,reset,updateAccountDetails,changeCurrentPassword,getCurrentUser};-----------



export {register,filterByPincode,getAllUsers,login,logout,getProfile,forgot,reset,calculateTotalRevenue,updateAccountDetails,changeCurrentPassword,getCurrentUser};
