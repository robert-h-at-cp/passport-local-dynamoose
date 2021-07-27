# Passport-Local Dynamoose

Passport-Local Dynamoose is a wrapper for [Dynamoose](https://dynamoosejs.com) inspired by [Passport-Local Mongoose](https://github.com/saintedlama/passport-local-mongoose) that simplifies building email and password login with [Passport](http://passportjs.org).

## Installation

```bash
> npm install https://github.com/robert-h-at-cp/passport-local-dynamoose
```

Passport-Local Dynamoose does not require `passport` or `dynamoose` dependencies directly but expects you to have these dependencies installed.

## Usage

### Plugin Passport-Local Dynamoose

First you need to plugin Passport-Local Mongoose into your User schema

```javascript
const dynamoose = require("dynamoose");
const { v4: uuidv4 } = require('uuid');
var passportLocalDynamoose = require('passport-local-dynamoose');

const UserSchema = new dynamoose.Schema({
  id: String,
  email: {
    type: String,
    index: [{ global: true, name: 'user-email-index' }],
  },
  encryptedPassword: String,
}, {
  timestamps: true,
});

const User = dynamoose.model("User", UserSchema);
// passport-local-dynamoose expects this document method to be defined so that it can invoke the method before saving the user
User.methods.document.set('generateIdIfMissing', function(cb) {
  const promise = Promise.resolve()
    .then(() => this.id = this.id || uuidv4())
    .then(() => this);

  if (!cb) {
    return promise;
  }

  promise.then(result => cb(null, result)).catch(err => cb(err));
});

passportLocalDynamoose(User);

module.exports = User;
```

You're free to define your User how you like. However Passport-Local Dynamoose do expect the fields to be defined in the example above, including `id`, `email`, `encryptedPassword`, as well as the global secondary index for the email field.

Additionally Passport-Local Dynamoose adds some methods to your Model and Document. See the [API Documentation](#api-documentation) section for more details.

### Configure Passport/Passport-Local

You should configure Passport/Passport-Local as described in [the Passport Guide](http://passportjs.org/guide/configure/).

Passport-Local Mongoose supports this setup by implementing a `LocalStrategy` and serializeUser/deserializeUser functions.

To setup Passport-Local Mongoose use this code

```javascript
// requires the model with Passport-Local Mongoose plugged in
const User = require('./models/user');

// use static authenticate method of model in LocalStrategy
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, function(email, password, done) {
  return User.authenticate().then((fn) => fn(email, password, done));
}));

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, done) {
  return User.serializeUser().then((fn) => fn(user, done));
});
passport.deserializeUser(function(id, done) {
  return User.deserializeUser().then((fn) => fn(id, done));
});
```

Make sure that you have a dynamoose connected to dynamodb and you're done.

#### Error Messages

Override default error messages by setting `options.errorMessages`.

* `MissingPasswordError`: 'No password was given'
* `AttemptTooSoonError`: 'Account is currently locked. Try again later'
* `TooManyAttemptsError`: 'Account locked due to too many failed login attempts'
* `NoSaltValueStoredError`: 'Authentication not possible. No salt value stored'
* `IncorrectPasswordError`: 'Password or username are incorrect'
* `IncorrectUsernameError`: 'Password or username are incorrect'
* `MissingUsernameError`: 'No username was given'
* `UserExistsError`: 'A user with the given username is already registered'

### Hash Algorithm

Passport-Local Dynamoose use the pbkdf2 algorithm of the node crypto library.
[Pbkdf2](http://en.wikipedia.org/wiki/PBKDF2) was chosen because platform independent
(in contrary to bcrypt). For every user a generated salt value is saved to make
rainbow table attacks even harder.

## API Documentation

### Instance methods

#### setPassword(password, [cb])

Sets a user password. Does not save the user object. If no callback `cb` is provided a `Promise` is returned.

#### changePassword(oldPassword, newPassword, [cb])

Changes a user's password hash and salt, resets the user's number of failed password attempts and saves the user object (everything only if oldPassword is correct). If no callback `cb` is provided a `Promise` is returned. If oldPassword does not match the user's old password, an `IncorrectPasswordError` is passed to `cb` or the `Promise` is rejected.

#### authenticate(password, [cb])

Authenticates a user object. If no callback `cb` is provided a `Promise` is returned.

### Callback Arguments

* `err`
  * null unless the hashing algorithm throws an error
* `thisModel`
  * the model getting authenticated **_if_** authentication was successful otherwise false
* `passwordErr`
  * an instance of `AuthenticationError` describing the reason the password failed, else undefined.

Using `setPassword()` will only update the document's password fields, but will not save the document.
To commit the changed document, remember to use Mongoose's `document.save()` after using `setPassword()`.

### Error Handling

* `IncorrectPasswordError`: specifies the error message returned when the password is incorrect. Defaults to 'Incorrect password'.
* `IncorrectUsernameError`: specifies the error message returned when the username is incorrect. Defaults to 'Incorrect username'.
* `MissingUsernameError`: specifies the error message returned when the username has not been set during registration. Defaults to 'Field %s is not set'.
* `MissingPasswordError`: specifies the error message returned when the password has not been set during registration. Defaults to 'Password argument not set!'.
* `UserExistsError`: specifies the error message returned when the user already exists during registration. Defaults to 'User already exists with name %s'.
* `NoSaltValueStored`: Occurs in case no salt value is stored in the MongoDB collection.
* `AttemptTooSoonError`: Occurs if the option `limitAttempts` is set to true and a login attept occures while the user is still penalized.
* `TooManyAttemptsError`: Returned when the user's account is locked due to too many failed login attempts.

All those errors inherit from `AuthenticationError`, if you need a more general error class for checking.

## License

Passport-Local Dynamoose is licenses under the [MIT license](http://opensource.org/licenses/MIT).
