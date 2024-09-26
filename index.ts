const express = require('express');
const bcrypt = require('bcryptjs');
const joi = require('joi');
const app = express();
const port = 3002;

import { Request, Response } from 'express';

interface UserDto {
  username: string;
  email: string;
  type: 'user' | 'admin';
  password: string;
}

interface UserEntry {
  email: string;
  type: 'user' | 'admin';
  salt: string;
  passwordhash: string;
}

// Database mock where the username is the primary key of a user.
const MEMORY_DB: Record<string, UserEntry> = {};

// CODE HERE
//
// I want to be able to register a new unique user (username and password). After the user is created I
// should be able to login with my username and password. If a user register request is invalid a 400 error
// should be returned, if the user is already registered a conflict error should be returned.
// On login the users crendentials should be verified.
// Because we dont have a database in this environment we store the users in memory. Fill the helper functions
// to query the memory db.

function getUserByUsername(name: string): UserEntry | undefined {
  return MEMORY_DB[name];
}

function getUserByEmail(email: string): UserEntry | undefined {
  return Object.values(MEMORY_DB).find((entry) => entry.email === email);
}

// Request body -> UserDto
app.post('/register', (req: Request, res: Response) => {
  // Validate user object using joi
  // - username (required, min 3, max 24 characters)
  // - email (required, valid email address)
  // - type (required, select dropdown with either 'user' or 'admin')
  // - password (required, min 5, max 24 characters, upper and lower case, at least one special character)
  const { username, email } = req.body;
  console.log('username:', username);
  if (getUserByUsername(username) || getUserByEmail(email)) {
    res.status(400).send({
      message: 'Conflicting user found in the database',
    });
  }
  const schema = joi.object({
    username: joi.string().alphanum().min(3).max(24).required(),
    email: joi.string().email().required(),
    type: joi.string().valid('user', 'admin').required(),
    password: joi
      .string()
      .min(5)
      .max(24)
      .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])'))
      .required(),
  });
  const { error, value } = schema.validate(req.body);
  if (error) {
    res.status(400).send({
      message: error.details[0].message,
    });
  } else {
    const salt = bcrypt.genSaltSync(10);
    const { email, type, password } = value;
    const passwordhash = bcrypt.hashSync(password, salt);
    MEMORY_DB[username] = {
      email,
      type,
      salt,
      passwordhash,
    };
  }
});

// Request body -> { username: string, password: string }
app.post('/login', (req: Request, res: Response) => {
  // Return 200 if username and password match
  // Return 401 else
  const INVALID_CREDENTIALS = {
    message: 'Invalid credentials',
  };
  const { username, password } = req.body;
  const user = getUserByUsername(username);
  if (!user) {
    res.status(401).send(INVALID_CREDENTIALS);
  }
  const matched = bcrypt.compareSync(password, user?.passwordhash);
  if (!matched) {
    res.status(401).send(INVALID_CREDENTIALS);
  }
  res.send({
    message: 'OK',
    data: { ...user, passwordhash: undefined, salt: undefined },
  });
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
