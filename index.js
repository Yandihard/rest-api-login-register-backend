const crypto = require('crypto');
const uuid = require('uuid');
const express = require('express');
const mysql = require('mysql');
// const bodyParser = require('body-parser');

//Connect to Mysql
const connect = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'nodejs-login-register-android'
});

const genRandomString = (length) => {
    return crypto.randomBytes(Math.ceil(length/2))
    .toString('hex') // Convert to hexa format
    .slice(0,length); // return required number of characters
};

const sha512 = (password, salt) => {
    const hash = crypto.createHmac('sha512', salt); //Use Sha512
    hash.update(password);
    const value = hash.digest('hex');
    return {
        salt: salt,
        passwordHash: value
    };
};

function saltHashPassword(userPassword) {
    const salt = genRandomString(16); //Generate random string with 16 character to salt
    const passwordData = sha512(userPassword, salt);
    return passwordData;
};

const checkHashPassword = (userPassword, salt) => {
    const passwordData = sha512(userPassword, salt);
    return passwordData
};

const app = express();
app.use(express.json());
app.use(express.urlencoded({extended: true}));

app.post('/register/', (req, res, next) => {

    const postData = req.body; //Get POST Params

    const uid = uuid.v4(); //Get UUID v4
    const plaintPassword = postData.password; //Get PASSWORD from POST Params
    const hashData = saltHashPassword(plaintPassword);
    const password = hashData.passwordHash; //Get hash value
    const salt = hashData.salt;

    const name = postData.name;
    const email = postData.email;

    connect.query('SELECT * FROM user where email=?', [email], function(err, result, fields) {
        connect.on('error', function(err) {
            console.log('[MySQL ERROR]', err);
        });
    if (result && result.length) {
        res.json('User already exist!');
    } else {
        connect.query('INSERT INTO `user`(`token_id`, `name`, `email`, `encrypted__password`, `salt`, `created_at`, `updated_at`) VALUES (?, ?, ?, ?, ?, NOW(), NOW())', [uid, name, email, password, salt], function(err, result, fields) {
            connect.on('error', function(err) {
                console.log('[MySQL ERROR]', err);
                res.json('Failed to register: ', err);
            });
            res.json('Register successfully');
        })
    }
});
});

app.post('/login/', (req, res, next) => {

    const postData = req.body;

    //Extract email & password from request
    const userPassword = postData.password;
    const email = postData.email;

    connect.query('SELECT * FROM user where email=?', [email], function(err, result, fields) {
        connect.on('error', function(err) {
            console.log('[MySQL ERROR]', err);
        });
    if (result && result.length) {
        const salt = result[0].salt; //Get salt from result if acccount has been exist
        const encryptedPassword = result[0].encrypted__password;
        //  Hash password from Login request with salt on database
        const hashedPassword = checkHashPassword(userPassword, salt).passwordHash;
        if (encryptedPassword == hashedPassword) {
            res.end(JSON.stringify(result[0])); //if password is true, return all info of user
        } else {
            res.end(JSON.stringify('Wrong Password!'));
        }
    } else {
        res.json('User not exist!');
    }
});
});

// app.get("/", (req, res, next) => {
//     console.log('Password: 123456');
//     const encrypt = saltHashPassword("123456");
//     console.log('Encrypt: '+encrypt.passwordHash);
//     console.log('Salt: '+encrypt.salt);
// })

//Start server
app.listen(3000, () => {
    console.log('Rest Server Running on port 3000');
})