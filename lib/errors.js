const generaterr = require('generaterr');

const AuthenticationError = generaterr('AuthenticationError');

module.exports = {
  AuthenticationError,
  IncorrectEmailError: generaterr('IncorrectEmailError', null, { inherits: AuthenticationError }),
  IncorrectPasswordError: generaterr('IncorrectPasswordError', null, { inherits: AuthenticationError }),
  MissingEmailError: generaterr('MissingEmailError', null, { inherits: AuthenticationError }),
  MissingPasswordError: generaterr('MissingPasswordError', null, { inherits: AuthenticationError }),
  UserExistsError: generaterr('UserExistsError', null, { inherits: AuthenticationError }),
  NoSaltValueStoredError: generaterr('NoSaltValueStoredError', null, { inherits: AuthenticationError }),
  AttemptTooSoonError: generaterr('AttemptTooSoonError', null, { inherits: AuthenticationError }),
  TooManyAttemptsError: generaterr('TooManyAttemptsError', null, { inherits: AuthenticationError }),
  PendingVerificationError: generaterr('PendingVerificationError', null, { inherits: AuthenticationError }),
};
