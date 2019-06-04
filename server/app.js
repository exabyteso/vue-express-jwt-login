'use strict'
const express = require('express'),
DB = require('./db'),
config = require('./config'),
argon2i = require('argon2-ffi').argon2i,
crypto = require('crypto'),
bcrypt = require('bcrypt'),
jwt = require('jsonwebtoken'),
bodyParser = require('body-parser'),

db = new DB('sqlitedb'),
app = express(),
router = express.Router();

router.use(bodyParser.urlencoded({ extended: false }))
router.use(bodyParser.json())

// CORS middleware
const allowCrossDomain = function(req, res, next) {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Headers', '*');
  next();
}

app.use(allowCrossDomain)

router.post('/register', function(req, res) {
  if(!req.body) return res.sendStatus(400); 

  let hash = crypto.randomBytes(512, function(err, salt){
    if(err) throw err;
    return argon2i.hash(req.body.password, salt).then(function(hash){
      return hash;
    });
  });
  
  db.insert([
    req.body.name,
    req.body.email,
    hash
  ],
  function (err) {
    if (err) return res.status(500).send('There was a problem registering the user.')
    db.selectByEmail(req.body.email, (err,user) => {
      if (err) return res.status(500).send('There was a problem getting user')
      let token = jwt.sign({ id: user.id }, config.secret, {expiresIn: 86400 // expires in 24 hours
      });
      res.status(200).send({ auth: true, token: token, user: user });
    }); 
  }); 
});

router.post('/register-admin', function(req, res) {
  if(!req.body) return res.sendStatus(400);

  let hash = crypto.randomBytes(512, function(err, salt){
    if(err) throw err;
    return argon2i.hash(req.body.password, salt).then(function(hash){
      return hash;
    });
  });

  db.insertAdmin([
    req.body.name,
    req.body.email,
    hash,
    1
  ],
  function (err) {
    if (err) return res.status(500).send("There was a problem registering the user.")
    db.selectByEmail(req.body.email, (err,user) => {
      if (err) return res.status(500).send("There was a problem getting user")
      let token = jwt.sign({ id: user.id }, config.secret, { expiresIn: 86400 // expires in 24 hours
      });
      res.status(200).send({ auth: true, token: token, user: user });
    }); 
  }); 
});

router.post('/login', (req, res) => {
  db.selectByEmail(req.body.email, (err, user) => {
    if (err) return res.status(500).send('Error on the server.');
    if (!user) return res.status(404).send('No user found.');
    let passwordIsValid = argon2i.verify(user.user_pass, req.body.password);
    if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });
    let token = jwt.sign({ id: user.id }, config.secret, { expiresIn: 86400 // expires in 24 hours
    });
    res.status(200).send({ auth: true, token: token, user: user });
  });
})

app.use(router)

let port = process.env.PORT || 3000;

let server = app.listen(port, function() {
  console.log('Express server listening on port ' + port)
});