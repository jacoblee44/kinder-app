// Messages are paid by segments and one segment is 160 characters 
// One segments cost $0.0833 
const Twilio = require('twilio')

//Spanish Twilio access
/*
// Live Key and Number
let accountSid = 'ACca1a5b6cd1c7710c088eaba4b1d61efe';
let authToken = 'c049fd446e1c17808ffcf71f650b1c5a';
let twilioNumber = '+4759446441';
*/

// Test Key and Number 
let accountSid = 'ACf7ddd1996544abf17f3dbecb0a79a8ec';
let authToken = 'a4a7455ba341e9a48a801090e322a6a3';
let twilioNumber = '+15005550006';

function getDateTime() {
    var date = new Date();
    var hour = date.getHours();
    hour = (hour < 10 ? "0" : "") + hour;
    var min  = date.getMinutes();
    min = (min < 10 ? "0" : "") + min;
    var sec  = date.getSeconds();
    sec = (sec < 10 ? "0" : "") + sec;
    var year = date.getFullYear();
    var month = date.getMonth() + 1;
    month = (month < 10 ? "0" : "") + month;
    var day  = date.getDate();
    day = (day < 10 ? "0" : "") + day;
    return year + ":" + month + ":" + day + ":" + hour + ":" + min + ":" + sec;
}

    let client = Twilio(accountSid, authToken);


exports.send_message = function(phoneNumber, textMessage) {
    return new Promise((res, rej) => {
        client.messages.create({
            //to: '+34644565080',
            to: phoneNumber,
            from: twilioNumber,
            body: textMessage,
        }).then((message) => {
            console.log("[Twilio] Message SENT: " + message.sid + ".");
            console.log(message);
            return res(message);
        }).catch((err) => {
            console.log("[Twilio] Error: ");
            console.log(err);
            return rej(err);
        });
    });
}
