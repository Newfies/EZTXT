/* Module Imports */
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const express = require('express');
const fetch = require('node-fetch');
const fs = require('fs');
const https = require('https');
const ini = require('ini');
const moment = require('moment-timezone');
const njs = require('newfiesjs');
const path = require('path');
const randomstring = require("randomstring");
const rateLimit = require('express-rate-limit');
const requestIP = require('request-ip');
const session = require('express-session');
const { createCanvas } = require('canvas');
const dotenv = require('dotenv').config();
const bcrypt = require('bcrypt');
const Datastore = require("nedb");
const db = new Datastore({ filename: "users.db", autoload: true });


/* Possible Additions; Not Added Yet */
// const cors = require('cors');
// const morgan = require('morgan');
// const compression = require('compression');

const app = express();
njs.config('reminderConfig', false)

/* Variables */
let timezone = process.env.TIMEZONE || "America/Chicago";
let rawCurrentDateTime = new Date();
let currentDateTime = moment(rawCurrentDateTime).tz(timezone).format('MMMM Do YYYY, h:mm:ss a');
const port = process.env.PORT || 3000;
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
    message: 'Too many requests, please try again later.',
});

/* Set */
// Set the view engine to ejs
app.set('view engine', 'ejs');

// Define the folder where the ejs files will be stored
app.set('views', path.join(__dirname, '/views'));

/* Use */
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true })); 
app.use(express.json());
app.use(cookieParser());
app.use(limiter);
app.use(requestIP.mw());
app.use(session({
  secret: process.env.SECRET_SESSION,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true }
}));

// Logs Requests By IP and Where - Im probably removing this, i just was curious about the middleware
app.use((req, res, next) => {
    const clientIp = req.clientIp;
    njs.njsLog(`Incoming request from IP: ${clientIp} - ${req.method} ${req.url}`);
    next();
});

/* Post */
app.post('/login', (req, res) => {
    const { username, password, action } = req.body;
    
    if (action === "Login"){
        res.send("Login pushied")
    }

    if (action === "Register"){
        
        db.findOne({ username: username }, (err, existingUser) => {
            if (err) {
                res.status(500).send("Database error");
                return;
            }
    
            if (existingUser) {
                // If the user already exists, send an error response
                res.status(400).send("User already in use");
            } else {
                // If the user does not exist, hash the password and create a new user
                bcrypt.hash(password, 13, (err, hashedPassword) => {
                    if (err) {
                        res.status(500).send("Error hashing password");
                        return;
                    }
    
                    const newUser = {
                        username: username,
                        password: hashedPassword,  // Store the hashed password
                        access: 0, // Access Level, Default Is 0 AKA "User"
                    };
    
                    db.insert(newUser, (err, newDoc) => {
                        if (err) {
                            res.status(500).send("Failed to create user");
                        } else {
                            res.send(`User ${newDoc.username} signed up successfully`);
                        }
                    });
                });
            }
        }
    )
    

    }

    else {

    }
});

/* Get */
app.get('/', function(req, res) {
    res.redirect("/login");
});

app.get('/login', function(req, res){
    res.render('login');
});

app.get('*', function(req, res) {
    res.redirect("/login");
});

/* Listen */
app.listen(port, () => {
    njs.njsLog(`Server is running on port ${port}`);
});