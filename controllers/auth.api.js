const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const config = require('../config/auth.js');
const auth = require('./auth');
const errors = require('./error');
const multer = require('multer');
const bcrypt = require('bcrypt');
const fs = require('fs');
require('dotenv').config();
// loading models
const Users = require('../models/Users');
const Child = require('../models/Child');
// loading middlewares
const validate = require('../middleware/validate');
const mailer = require('../middleware/mailer');
const crypthelper = require('../middleware/crypthelper');
const twiliohelper = require('../middleware/twiliohelper');
const expohelper = require('../middleware/expohelper');

//************** ROUTES ************************
router.post('/signup', (req, res) => {
	auth
		.registerUser(
			req.body.fullName,
			req.body.mobileNumber,
			req.body.email.toLowerCase(),
			req.body.password,
			req.body.sms1,
			req.body.sms2
		)
		.then(user => {
			auth.logUserActivity(user, 'signup');
		})
		.then(() => {
			res.send({
				success: true
			});
		})
		.catch(err => {
			return errors.errorHandler(res, err);
		});
});

router.post('/login', (req, res) => {
	auth
		.loginUser(req.body.email.toLowerCase(), req.body.password)
		.then(user => {
			let authToken = auth.createToken(user);
			let refreshToken = auth.createRefreshToken(user);
			let userActivityLog = auth.logUserActivity(user, 'login');
			return Promise.all([
				authToken,
				refreshToken,
				userActivityLog
			]).then(tokens => {
				return {
					authToken: tokens[0],
					refreshToken: tokens[1]
				};
			});
		})
		.then(success => {
			res.send({
				success: true,
				authToken: success.authToken,
				refreshToken: success.refreshToken
			});
		})
		.catch(err => {
			return errors.errorHandler(res, err);
		});
});

router.post('/refreshToken', (req, res) => {
	auth
		.validateRefreshToken(req.body.refreshToken)
		.then(tokenResponse => {
			return auth.createToken(tokenResponse);
		})
		.then(authToken => {
			res.status(200).send({
				success: true,
				authToken: authToken
			});
		})
		.catch(err => {
			if (err.code) {
				return errors.errorHandler(res, err.message, err.code);
			} else {
				return errors.errorHandler(res, err.message);
			}
		});
});

// FORGOT PASSWORD --------------------
// check user email exists in DB and set resetToken
router.post('/forgotten', (req, res) => {

    // check if any data missing
    if (!req.body.email || !validate.checkString(req.body.email) || !validate.checkEmail(req.body.email)) {
        return errors.errorHandler(res, "You must provide a valid email address");
    }

    
    Users.findOne({email: req.body.email.toLowerCase() }).then(user=>{
    	if(!user){
    		return errors.errorHandler(res, "Can't find user with this email!");
		}
		// ======================================
		const ts = new Date().getTime();
		let resetcode = "";
    	resetcode += user._id;
    	resetcode += "_"+user.email;
    	resetcode += "_"+ (ts);
		resetcode = crypthelper.aesEncode( resetcode);


        const mailbody = '<h4>To reset password visit below link!</h4>'
		+'<a href="'+ process.env.SERVER_HOST+':'+process.env.PORT  +'/api/auth/reset/'+resetcode+'">Reset Password</a>';
        mailer.sendmail( req.body.email, 'Reset your password', mailbody )
        .then( info =>{
            res.status(200).send({success:true, data: info });
        }).catch(err => {
            return errors.errorHandler(res, err.message);
        });
        // =============================
	}).catch(err1=>{
        return errors.errorHandler(res, err1.message);
	});

});
// check a reset link is valid
function checkResetCodeFormat( resetCode ) {
    let mystr = "";
    try {
        mystr = crypthelper.aesDecode(resetCode);
    }catch(e){
        return {success: false, msg: e.message};
    }
    const p = mystr.split("_");
    if (p.length !==3) {
        return {success: false, msg: "Invalid reset code"};
    }
    const ts = Number(p[2]);
    if (ts === Number.NaN) {
        return {success: false, msg: "Invalid reset code"};
    }
    const nowts = Date.now();
    console.log(nowts);
    console.log(ts);

    // reset password token is available for 5 minutes!
    if( nowts - ts > 5*60*1000|| nowts < ts ){
        return {success: false, msg: "Reset code time is expired! Try again to get forgot password service!"};
	}
	return {success: true, msg:"ok", data: p};
}

// display reset password page!
router.get('/reset/:resetCode', (req, res) => {
	const ret = checkResetCodeFormat(req.params.resetCode);
	if (!ret.success) {
        return res.render("forgotpwd", {errmsg: ret.msg});
	}

    Users.findOne({_id: ret.data[0], email: ret.data[1]})
    .then( user => {
        if ( !user ) {
            return res.render("forgotpwd", {errmsg: "Invalid reset code"});
        }
        return res.render("forgotpwd" , {resetCode: req.params.resetCode});
    })
    .catch( err => {
        return errors.errorHandler(res, err.message);
    });

});
// take password data and set new password
router.post('/password/reset', (req, res) => {
    if ( !req.body.resetCode || !req.body.newpwd) {
        return res.render('goback.ejs',{
            message: "Required Parameters are missing!"
        });
    }
    const ret = checkResetCodeFormat(req.body.resetCode);
    if (!ret.success) {
        return res.render('goback.ejs',{
            message:  ret.msg
        });
    }
    const pwdhash =  bcrypt.hashSync(req.body.newpwd.trim(), 12);
    Users.findOneAndUpdate({_id: ret.data[0], email: ret.data[1]},  {$set: {'password': pwdhash} } ,{ new:true})
    .then( user => {
        if ( !user ) {
            return res.render('goback.ejs',{
                message: "Invalid reset code!"
            });
        }
        return res.render('goback.ejs',{
            message:  "OK! Your password is changed successfully!"
        });
    })
    .catch( err => {
        return errors.errorHandler(res, err.message);
    });

});




router.post('/notice_parent', async(req, res) => {
    if (!req.body.bandId || !req.body.finderNumber) {
        return errors.errorHandler(res, "Missing Required Parameters");
    }

    Child.find({ bandId: req.body.bandId })
    .then( existchilds => {
        if ( existchilds.length == 0){
            throw new Error("This band ID is not exist in database!");
        }
        return Users.find({ _id: existchilds[0].userId });
    })
    .then( async(parents) => {
        if ( parents.length == 0){
            throw new Error("Parent of this band ID is not exist in database!");
        }
        // ===========================================================
        const parent = parents[0];
        let success_sms = false, 
        success_push = false, 
        result_data = {} , // result_data['sms'] , result_data['push'] 
        error_message_sms = "",
        error_message_push = "";
        /** 
         * Sending SMS using Twilio API
        */
        let msg = "Hello, I am KinderApp";
        msg += " Someboy find your child. Please dial this mobile number !"
        msg += " "+req.body.finderNumber;
        try {
            const ret = await twiliohelper.send_message( parent.mobileNumber, msg);        
            success_sms = true;
            result_data['sms'] = ret;
        } catch (err) {        
            success_sms = false;
            if ( err.code == 21211 ) {
                error_message_sms += "Parent's phone number is not valid! "+err.message;
            }else {
                error_message_sms += "SERVER Twilio ISSUE: "+err.message;
            }
        }        
        /** 
         * Sending Push Notification using Expo
        */
        console.log("[Expo]");
        if ( parent.pushToken ) {
            try {
                const ret = await expohelper.send_message( [ parent.pushToken ], msg); 
                success_push = true;
                result_data['push'] = ret;
            }catch( err ) {
                console.error(err);
                error_message_push += err.message;
            }
        } else {
            error_message_push+="Parent doesn't have pushToken.";
        }
        /**
         * RETURN RESULT
         *  */ 
        if ( !success_sms || !success_push ) {
            return res.status(400).send({
                success: false,
                message_sms: error_message_sms,
                message_push: error_message_push,
                success_sms: success_sms,
                success_push: success_push,
                data: result_data
            });
        } 
        // Everything is success !       
        return res.status(200).send({
            success: true,
            data: result_data,
            // --------
            success_sms: success_sms,
            success_push: success_push
        });
    })
    .catch( err=> {
        return errors.errorHandler(res, err.message);
    });
});

//====================== Private Routes from Now=====================================
router.use((req, res, next) => {
    var token = req.headers['authorization'];
    token = token.replace('Bearer ', '');
    return jwt.verify(token, config.secret, (jwtErr, decoded) => {
        if (jwtErr) {
        	console.log(token);
            return errors.errorHandler(
                res,
                'Your access token is invalid.',
                'invalidToken'
            );
        } else {
        	req._auth = decoded;
            next();
        }
    });
});
/*
router.post('/getAll', (req, res) => {
	Users.find()
		.then(users => {
			res.status(201).send({
				success: true,
				message: users
			});
		})
		.catch(err => {
			return errors.errorHandler(res, err);
		});
});
*/

// get my profile
router.get('/get_my_profile', (req, res) => {
    // check if any data missing

    Users.findOne(
        {_id: req._auth._id}
    ).then(obj=>{

        res.status(200).send({
            success: true,
            data: {
                "email" : obj.email,
                "fullName" : obj.fullName,
                "mobileNumber" : obj.mobileNumber,
                "sms1" : obj.sms1,
                "sms2" : obj.sms2
            }
        });
    }).catch( err=> {
    return errors.errorHandler(res, err.message);
    });
});
// update user 's profile
router.post('/update_profile', async(req, res) => {
	// check if any data missing
    if (!req.body.fullName || !req.body.mobileNumber  ) {
        return errors.errorHandler(res, "Required Parameters are missing!");
    }

    const newdata = {
        'fullName': req.body.fullName, 'mobileNumber': req.body.mobileNumber
    };
    if (req.body.email && req._auth.email !==req.body.email ) {
        newdata['email'] = req.body.email;
        const existusers = await Users.find({ email: req.body.email }).exec();
        if (existusers.length){
            return errors.errorHandler(res, "Email address is already in use!");
        }
    }
    if (req.body.password) {
        const pwdhash =  bcrypt.hashSync(req.body.password.trim(), 12);
        newdata['password'] = pwdhash;
    }
    if (req.body.sms1) {
        newdata['sms1'] = req.body.sms1;
    }
    if (req.body.sms2) {
        newdata['sms2'] = req.body.sms2;
    }

    Users.findOneAndUpdate(
        {_id: req._auth._id}, {$set: newdata } ,{ new:true}
    )
    .then(obj=>{
        res.status(200).send({
            success: true,
            data: obj
        });
    }).catch( err=> {
        return errors.errorHandler(res, err.message);
    });
});

// update user 's password
router.post('/update_password', (req, res) => {
    // check if any data missing
    if (!req.body.newpwd ) {
        return errors.errorHandler(res, "New password is missing!");
    }
	const pwdhash =  bcrypt.hashSync(req.body.newpwd.trim(), 12);
    Users.findOneAndUpdate(
        {_id: req._auth._id}, {$set: {'pushtoken':pwdhash} } ,{ new:true}
    )
    .then(obj=>{
        res.status(200).send({
            success: true,
            data: obj
        });
    }).catch( err=> {
        return errors.errorHandler(res, err.message);
    });
});

// update user 's pushtoken
router.post('/update_pushtoken', (req, res) => {
    // check if any data missing
    if (!req.body.pushToken ) {
        return errors.errorHandler(res, "Pushtoken parameter is missing!");
    }
    Users.findOneAndUpdate(
        {_id: req._auth._id}, {$set: {'pushToken':req.body.pushToken} } ,{ new:true}
    )
    .then(obj=>{
        res.status(200).send({
            success: true,
            data: obj
        });
    }).catch( err=> {
        return errors.errorHandler(res, err.message);
    });
});

/*==== Child APIs======*/
const storage1 = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, './public/uploads')
    },
    filename: function (req, file, cb) {
    	console.log(file);
        cb(null, file.fieldname +'_'+req._auth._id+ '_' + Date.now()+'_'+file.originalname);
    }
});
function path2url( filepath ) {
    if ( !filepath )
        return "";
    if (filepath.indexOf("./public")!=-1)
        return filepath.replace("./public", "");
    if (filepath.indexOf("public/")!=-1)
        return filepath.replace("public/", "");
    else
        return filepath;
}

// add new child to user
router.post('/child/add', multer({storage: storage1}).single('photo'), async(req, res) => {
    // check if any data missing
    if (!req.body.name || !req.body.bandId || !req.body.activationCode ) {
        return errors.errorHandler(res, "Required Parameters are missing!");
    }
    
    if (!(/^[A-Z]{2} [0-9]{6}$/.test(req.body.bandId))){
        return errors.errorHandler(res, "Band Id must be {2 english letters, space and then 6 digits}!");
    }
    if (!(/^[A-Z0-9]{6}$/.test(req.body.activationCode))){
        return errors.errorHandler(res, "ActivationCode length must be 6. Only digits and letters are available!");
    }

    const existchilds = await Child.find({ bandId: req.body.bandId }).exec();
    if ( existchilds.length > 0){
        return errors.errorHandler(res, "This band id is already in use!");
    }

    const newChild = new Child({
		name : req.body.name,
		bandId: req.body.bandId,
		activationCode: req.body.activationCode,
		userId: req._auth._id,
        path: (req.file?req.file.destination+"/"+req.file.filename:""),
        pathurl: path2url(req.file?req.file.destination+"/"+req.file.filename:"")
	});

    newChild.save().then(obj=>{
        res.status(200).send({
            success: true,
            data: obj
        });
	}).catch( err=> {
        return errors.errorHandler(res, err.message);
	});
});


// update a single child
router.post('/child/update/:childId', multer({storage: storage1}).single('photo'), async(req, res) => {
    // check if any data missing
    let newData = {};
    if (req.body.name) {
        newData['name'] = req.body.name;
    }
    if (req.body.bandId) {
        if (!(/^[A-Z]{2} [0-9]{6}$/.test(req.body.bandId))){
            return errors.errorHandler(res, "Band Id must be {2 english letters, space and then 6 digits}!");
        }
        const existchilds = await Child.find({ bandId: req.body.bandId }).exec();
        let aluse = false;
        for (key in existchilds ) {
            if (existchilds[key]._id == req.params.childId) {
                continue;
            }
            aluse = true;
        }
        if ( aluse){
            return errors.errorHandler(res, "This band id is already in use!");
        }
        
        newData['bandId'] = req.body.bandId;
    }
    if (req.body.activationCode) {
        if (!(/^[A-Z0-9]{6}$/.test(req.body.activationCode))){
            return errors.errorHandler(res, "ActivationCode length must be 6. Only digits and letters are available!");
        }
        newData['activationCode'] = req.body.activationCode; 
    }
    
    console.log( req.file);
    Child.findOne(
        {_id: req.params.childId}
    ).then( child=> {
        if (!child) {
            throw new Error("The child with this id doesn't exist!");
        }
        if (child['userId']!== req._auth._id) {
            throw new Error("This is not your child!");
        }
        if (req.file) {
            newData['path'] = (req.file?req.file.destination+"/"+req.file.filename:"");
            newData['pathurl'] = path2url( newData['path']);
            // If new file exist, delete old.
            if (child["path"] && fs.existsSync(child["path"])) {
                fs.unlinkSync(child["path"]);
            }
        }
        return Child.findOneAndUpdate(
            {_id: req.params.childId}, {$set: newData} ,{ new:true}
        );
    }).then( updated_obj=>{
        res.status(200).send({
            success: true,
            data: updated_obj
        });
    })
    .catch( err=> {
        return errors.errorHandler(res, err.message);
    });

});

// delete a single child
router.get('/child/delete/:childId', (req, res) => {
    Child.findOne(
        {_id: req.params.childId}
    ).then( child=> {
        if (!child) {
            throw new Error("The child with this id doesn't exist!");
        }
        if (child['userId']!== req._auth._id) {
            throw new Error("This is not your child!");
        }
        if (child["path"] && fs.existsSync(child["path"])) {
            fs.unlinkSync(child["path"]);
        }
        return Child.findByIdAndRemove(req.params.childId);
    }).then( del_obj=>{
        res.status(200).send({
            success: true,
            data: del_obj
        });
    })
    .catch( err=> {
        return errors.errorHandler(res, err.message);
    });


});

// get user 's child list
router.get('/child/getMyChildren', (req, res) => {
    // check if any data missing
    console.log("Get Children of :"+ req._auth._id);
    Child.find({userId: req._auth._id}).then( children=>{
        res.status(200).send({
            success: true,
            data: children
        });
    }).catch( err=> {
        return errors.errorHandler(res, err.message);
    });
});

// get user 's single child
router.get('/child/getMyChild/:childId', (req, res) => {
    // check if any data missing
    console.log("Get Child "+req.params.childId+" of "+ req._auth._id);
    Child.findOne(
        {_id: req.params.childId}
    ).then( child=> {
        if (!child) {
            throw new Error("The child with this id doesn't exist!");
        }
        if (child['userId']!== req._auth._id) {
            throw new Error("This is not your child!");
        }
        res.status(200).send({
            success: true,
            data: child
        });
    })
    .catch( err=> {
        return errors.errorHandler(res, err.message);
    });
});

module.exports = router;
