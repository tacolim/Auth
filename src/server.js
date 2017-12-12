const bodyParser = require('body-parser');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');

const User = require('./user.js');

const STATUS_USER_ERROR = 422;
const STATUS_SERVER_ERROR = 500;
const BCRYPT_COST = 11;

const server = express();
// to enable parsing of json bodies for post requests
server.use(bodyParser.json());
server.use(session({
  secret: 'e5SPiqsEtjexkTj3Xqovsjzq8ovjfgVDFMfUzSmJO21dtXs4re'
}));

/* Sends the given err, a string or an object, to the client. Sets the status
 * code appropriately. */
const sendUserError = (err, res) => {
  res.status(STATUS_USER_ERROR);
  if (err && err.message) {
    res.json({ message: err.message, stack: err.stack });
  } else {
    res.json({ error: err });
  }
};

// TODO: implement routes

const hashPass = (req, res, next) => {
  const { password } = req.body;
  bcrypt
    .hash(password, BCRYPT_COST)
    .then((pw) => {
      req.password = pw;
      next();
    })
    .catch((err) => {
      throw new Error(err);
    });
};

server.post('/users', hashPass, (req, res) => {
  const username = req.body;
  const passwordHash = req.password;

  const newUser = new User({ username, passwordHash });

  newUser.save((err, savedUser) => {
    if (err) {
      res.status(STATUS_USER_ERROR);
      res.json({ 'Need email & pw': err.message });
      return;
    }
    res.status(200).json(savedUser);
  });
});

const authenticate = (req, res, next) => {
  const { username, password } = req.body;
  User.findOne({ username }, (err, user) => {
    if (err) {
      res.status(STATUS_USER_ERROR);
      res.json({ 'Need both Email/PW': err.message });
      return;
    }
    const hashedPW = user.passwordHash;
    bcrypt
      .compare(password, hashedPW)
      .then((res) => {
        if (!res) throw new Error();
        req.loggedInUser = user;
        next();
      })
      .catch((err) => {
        return sendUserError('some err message', res);
      });
  });
};

server.post('/log-in', authenticate, (req, res) => {
  res.json({ success: true });
});

const loggedIn = (req, res, next) => {
  const { username, password } = req.body;
  User.findOne({ username }, (err, user) => {
    if (err) {
      res.status(STATUS_USER_ERROR);
      res.json({ 'Need both Email/PW': err.message });
      return;
    }
    const hashedPW = user.passwordHash;
    bcrypt
      .compare(password, hashedPW)
      .then((res) => {
        if (!res) throw new Error();
        req.loggedInUser = user;
        next();
      })
      .catch((err) => {
        return sendUserError('some err message', res);
      });
  });
};

// TODO: add local middleware to this route to ensure the user is logged in
server.get('/me', (req, res) => {
  // Do NOT modify this route handler in any way.
  res.json(req.user);
});

module.exports = { server };
