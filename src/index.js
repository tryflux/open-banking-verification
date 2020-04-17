const config = require('./config');
const { checkSignature } = require('./checkSignature');
checkSignature(config.sigToCheck, config.expectedPayload, config.keystoreUrl);
