'use strict';
var nodemailer = require('nodemailer');
//Load environment variables
require('dotenv').config();

var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'husseindib8000@gmail.com',
        pass: 'Aptx48691234'
    }
});

// numerical encoding of some allowed special characters
exports.sendmail = function(receiver , subject, html) {
    return new Promise((res, rej) => {
        transporter.sendMail({
            from: '', // sender address - useless in  gmail
            to: receiver, // list of receivers
            subject: subject, // Subject line
            html: html // plain text body
        }, function (err, info) {
            if(err)
                return rej(err);
            else
                return res(info);
        });
        // =====================
    });
};
