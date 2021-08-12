const scmp = require('scmp');

const pbkdf2 = require('./pbkdf2');
const errors = require('./errors');

// authenticate function needs refactoring - to avoid bugs we wrapped a bit dirty
module.exports = function(user, password, options, cb) {
  if (cb) {
    return authenticate(user, password, options, (err, user, error) => cb(err, { user, error }));
  }

  return new Promise((resolve, reject) => {
    authenticate(user, password, options, (err, user, error) => (err ? reject(err) : resolve({ user, error })));
  });
};

function authenticate(user, password, options, cb) {
  if (options.limitAttempts) {
    const attemptsInterval = Math.pow(options.interval, Math.log(user[options.attemptsField] + 1));
    const calculatedInterval = attemptsInterval < options.maxInterval ? attemptsInterval : options.maxInterval;

    if (Date.now() - user[options.lastLoginField] < calculatedInterval) {
      user.set(options.lastLoginField, Date.now());
      user.save(function(saveErr) {
        if (saveErr) {
          return cb(saveErr);
        }
        return cb(null, false, new errors.AttemptTooSoonError(options.errorMessages.AttemptTooSoonError));
      });
      return;
    }

    if (user[options.attemptsField] >= options.maxAttempts) {
      return cb(null, false, new errors.TooManyAttemptsError(options.errorMessages.TooManyAttemptsError));
    }
  }

  if (options.confirmable) {
    if (!user.confirmedAt) {
      return cb(null, false, new errors.PendingVerificationError(options.errorMessages.PendingVerificationError));
    }
  }

  let encryptedPassword = user.encryptedPassword;
  let salt = null;
  let hash = null;

  if (encryptedPassword && encryptedPassword.length >= 3) {
    encryptedPassword = encryptedPassword.split('.');
    if (encryptedPassword.length == 2) {
      salt = encryptedPassword[0];
      hash = encryptedPassword[1]
    }
  }

  if (!salt) {
    return cb(null, false, new errors.NoSaltValueStoredError(options.errorMessages.NoSaltValueStoredError));
  }

  pbkdf2(password, salt, options, function(err, hashBuffer) {
    if (err) {
      return cb(err);
    }

    if (scmp(hashBuffer, Buffer.from(hash, options.encoding))) {
      if (options.limitAttempts) {
        user[options.lastLoginField] = Date.now();
        user[options.attemptsField] = 0
        user.save(function(saveErr, user) {
          if (saveErr) {
            return cb(saveErr);
          }
          return cb(null, user);
        });
      } else {
        return cb(null, user);
      }
    } else {
      if (options.limitAttempts) {
        user[options.lastLoginField] = Date.now();
        user[options.attemptsField] = user[options.attemptsField] + 1;
        user.save(function(saveErr) {
          if (saveErr) {
            return cb(saveErr);
          }
          if (user.get(options.attemptsField) >= options.maxAttempts) {
            return cb(null, false, new errors.TooManyAttemptsError(options.errorMessages.TooManyAttemptsError));
          } else {
            return cb(null, false, new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError));
          }
        });
      } else {
        return cb(null, false, new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError));
      }
    }
  });
}
