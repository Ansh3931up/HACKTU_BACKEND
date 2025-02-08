import { Router } from "express";
import {register,filterByPincode,login,logout,getProfile,getAllUsers,forgot,reset,updateAccountDetails,changeCurrentPassword,getCurrentUser, calculateTotalRevenue} from "../controllers/user.controller.js";
import {upload} from "../middleware/multer.middleware.js"
import { authorizedRoles, verifyjwt } from "../middleware/auth.middleware.js";
const router=Router();

router.route("/register").post(upload.single("avatar"),register);
router.route("/login").post(login);
router.route("/logout").post(verifyjwt,logout);
router.route("/me").post(verifyjwt,getProfile);
router.route("/reset").post(forgot);
router.route("/reset/:resetToken").post(reset);
router.route("/user-details").post(verifyjwt,getCurrentUser);
router.route("/change-password").post(verifyjwt,changeCurrentPassword);
router.route("/change-details").post(verifyjwt,updateAccountDetails);
router.route("/alldata").get(verifyjwt,authorizedRoles("ADMIN"),getAllUsers);

export default router;