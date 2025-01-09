const bcrypt        = require('bcrypt');
const passport      = require('passport');
const UserModel     = require('../model/model');
const localStrategy = require('passport-local').Strategy;

passport.use(
    'signup',
    new localStrategy(
      {
        usernameField: 'email',
        passwordField: 'password'
      },
      async (email, password, done) => {
        try {
          const salt = await bcrypt.genSaltSync(10); // add salt
          const hash = await bcrypt.hash(password, salt);
          password = hash;
          const user = await UserModel.create({ email, password });
          return done(null, user);
        } catch (error) {
          done(error);
        }
      }
    )
);

passport.use(
    'login',
    new localStrategy(
      {
        usernameField: 'email',
        passwordField: 'password'
      },
      async (email, password, done) => {
        try {
          const user = await UserModel.findOne({ email });
          if (!user) {
            return done(null, false, { message: 'User not found' });
          }
          const validate = await bcrypt.compare(password, user.password);
          console.log ('validate (bcrypt.compare):', validate);
          if (!validate) {
            return done(null, false, { message: 'Wrong Password' });
          }
          return done(null, user, { message: 'Logged in Successfully' });
        } catch (error) {
          return done(error);
        }
      }
    )
);

const JWTstrategy = require('passport-jwt').Strategy;
const ExtractJWT  = require('passport-jwt').ExtractJwt;
  
passport.use(
    new JWTstrategy(
      {
        secretOrKey: 'JWT',
        jwtFromRequest: ExtractJWT.fromUrlQueryParameter('secret_token')
      },
      async (token, done) => {
        try {
          return done(null, token.user);
        } catch (error) {
          done(error);
        }
      }
    )
);