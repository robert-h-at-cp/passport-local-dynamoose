const crypto = require('crypto');
const LocalStrategy = require('passport-local').Strategy;

const pbkdf2 = require('./lib/pbkdf2');
const errors = require('./lib/errors');
const authenticate = require('./lib/authenticate');

module.exports = function(model, options) {
  options = options || {};
  options.saltlen = options.saltlen || 32;
  options.iterations = options.iterations || 25000;
  options.keylen = options.keylen || 512;
  options.encoding = options.encoding || 'hex';
  options.digestAlgorithm = options.digestAlgorithm || 'sha256'; // To get a list of supported hashes use crypto.getHashes()

  function defaultPasswordValidator(password, cb) {
    cb(null);
  }

  function defaultPasswordValidatorAsync(password) {
    return new Promise((resolve, reject) => {
      options.passwordValidator(password, err => (err ? reject(err) : resolve()));
    });
  }

  options.passwordValidator = options.passwordValidator || defaultPasswordValidator;
  options.passwordValidatorAsync = options.passwordValidatorAsync || defaultPasswordValidatorAsync;

  // Populate field names with defaults if not set
  options.emailField = options.emailField || 'email';
  options.emailUnique = options.emailUnique === undefined ? true : options.emailUnique;

  // Populate email query fields with defaults if not set,
  // otherwise add email field to query fields.
  if (options.emailQueryFields) {
    options.emailQueryFields.push(options.emailField);
  } else {
    options.emailQueryFields = [options.emailField];
  }

  // option to find email case insensitively
  options.emailCaseInsensitive = Boolean(options.emailCaseInsensitive || false);

  // option to convert email to lowercase when finding
  options.emailLowerCase = options.emailLowerCase || false;

  if (options.limitAttempts) {
    options.lastLoginField = options.lastLoginField || 'last';
    options.attemptsField = options.attemptsField || 'attempts';
    options.interval = options.interval || 100; // 100 ms
    options.maxInterval = options.maxInterval || 300000; // 5 min
    options.maxAttempts = options.maxAttempts || Infinity;
  }

  options.confirmable = options.confirmable || false;

  options.errorMessages = options.errorMessages || {};
  options.errorMessages.MissingPasswordError = options.errorMessages.MissingPasswordError || 'No password was given';
  options.errorMessages.AttemptTooSoonError = options.errorMessages.AttemptTooSoonError || 'Account is currently locked. Try again later';
  options.errorMessages.TooManyAttemptsError =
    options.errorMessages.TooManyAttemptsError || 'Account locked due to too many failed login attempts';
  options.errorMessages.NoSaltValueStoredError =
    options.errorMessages.NoSaltValueStoredError || 'Authentication not possible. No salt value stored';
  options.errorMessages.IncorrectPasswordError = options.errorMessages.IncorrectPasswordError || 'Password or email is incorrect';
  options.errorMessages.IncorrectEmailError = options.errorMessages.IncorrectEmailError || 'Password or email is incorrect';
  options.errorMessages.MissingEmailError = options.errorMessages.MissingEmailError || 'No email was given';
  options.errorMessages.UserExistsError = options.errorMessages.UserExistsError || 'A user with the given email is already registered';
  options.errorMessages.PendingVerificationError = options.errorMessages.PendingVerificationError || 'You have to verify your email before continuing';

  model.methods.document.set('setPassword', function(password, cb) {
    let _salt = null;
    const promise = Promise.resolve()
      .then(() => {
        if (!password) {
          throw new errors.MissingPasswordError(options.errorMessages.MissingPasswordError);
        }
      })
      .then(() => options.passwordValidatorAsync(password))
      .then(() => randomBytes(options.saltlen))
      .then(saltBuffer => saltBuffer.toString(options.encoding))
      .then(salt => {
        _salt = salt;

        return salt;
      })
      .then(salt => pbkdf2Promisified(password, salt, options))
      .then(hashRaw => {
        this.encryptedPassword = `${_salt}.${Buffer.from(hashRaw, 'binary').toString(options.encoding)}`;
      })
      .then(() => this);

    if (!cb) {
      return promise;
    }

    promise.then(result => cb(null, result)).catch(err => cb(err));
  });

  model.methods.document.set('changePassword', function(oldPassword, newPassword, cb) {
    const promise = Promise.resolve()
      .then(() => {
        if (!oldPassword || !newPassword) {
          throw new errors.MissingPasswordError(options.errorMessages.MissingPasswordError);
        }
      })
      .then(() => this.authenticate(oldPassword))
      .then(({ user }) => {
        if (!user) {
          throw new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError);
        }
      })
      .then(() => this.setPassword(newPassword))
      .then(() => this.save())
      .then(() => this);

    if (!cb) {
      return promise;
    }

    promise.then(result => cb(null, result)).catch(err => cb(err));
  });

  model.methods.document.set('authenticate', function(password, cb) {
    const promise = Promise.resolve().then(() => {
      return authenticate(this, password, options);
    });

    if (!cb) {
      return promise;
    }

    promise.then(({ user, error }) => cb(null, { user, error })).catch(err => cb(err));
  });

  // Passport Local Interface
  model.methods.set('authenticate', async function() {
    return (email, password, cb) => {
      const promise = Promise.resolve()
        .then(() => this.findByEmail(email))
        .then(user => {
          if (user) {
            return user.authenticate(password);
          }

          return { user: false, error: new errors.IncorrectEmailError(options.errorMessages.IncorrectEmailError) };
        });

      if (!cb) {
        return promise;
      }

      promise.then(({ user, error }) => cb(null, user, error)).catch(err => cb(err));
    };
  });

  // Passport Interface
  model.methods.set('serializeUser', async function() {
    return function(user, cb) {
      cb(null, user.id);
    };
  });

  model.methods.set('deserializeUser', async function() {
    return (id, cb) => {
      this.findById(id, (err, user) => {
        if (err) { return cb(err, false); }
        if (options.confirmable && !user.confirmedAt) { return cb(new errors.PendingVerificationError(options.errorMessages.PendingVerificationError), false); }
        return cb(null, user);
      });
    };
  });

  model.methods.set('register', function(user, password, cb) {
    // Create an instance of this in case user isn't already an instance
    if (!(user instanceof model)) {
      user = new model(user);
    }

    const promise = Promise.resolve()
      .then(() => {
        if (!user[options.emailField]) {
          throw new errors.MissingEmailError(options.errorMessages.MissingEmailError);
        }
      })
      .then(() => this.findByEmail(user[options.emailField]))
      .then(existingUser => {
        if (existingUser) {
          throw new errors.UserExistsError(options.errorMessages.UserExistsError);
        }
      })
      .then(() => user.setPassword(password))
      .then(() => user.generateIdIfMissing())
      .then(() => user.save());

    if (!cb) {
      return promise;
    }

    promise.then(result => cb(null, result)).catch(err => cb(err));
  });

  model.methods.set('findByEmail', function(email, cb) {
    // if specified, convert the email to lowercase
    if (email !== undefined && options.emailLowerCase) {
      email = email.toLowerCase();
    }

    model.query('email').eq(email).using('user-email-index').limit(1).exec().then(function(result) {
      result = result.count >= 1 ? result[0] : null;

      if (cb) {
        cb(null, result);
        return;
      }

      return result;
    });
  });

  model.methods.set('findById', function(id, opts, cb) {
    if (typeof opts === 'function') {
      cb = opts;
      opts = {};
    }

    opts = opts || {};

    if (cb) {
      model.get(id, cb);
      return;
    }

    return model.get(id);
  });

  model.methods.set('createStrategy', function() {
    return new LocalStrategy(options, this.authenticate());
  });
};

function pbkdf2Promisified(password, salt, options) {
  return new Promise((resolve, reject) => pbkdf2(password, salt, options, (err, hashRaw) => (err ? reject(err) : resolve(hashRaw))));
}

function randomBytes(saltlen) {
  return new Promise((resolve, reject) => crypto.randomBytes(saltlen, (err, saltBuffer) => (err ? reject(err) : resolve(saltBuffer))));
}

module.exports.errors = errors;
