const jose = require('jose');
const request = require('request');
const { assert } = require('./assert');

const joseOpts = {
  crit: ['b64', 'typ', 'kid', 'cty', 'alg', 'crit']
};

async function checkSignature(signatureToCheck, expectedPayload, keystoreUrl) {
  // Get the keystore from the keystore url.
  const keystore = await getKeystore(keystoreUrl);
  // Check that the signature is valid.
  const result = await validateSignature(
    keystore,
    expectedPayload,
    signatureToCheck
  );
  console.log('INFO: result=', result);
}
module.exports.checkSignature = checkSignature;

async function validateSignature(keystore, expectedPayload, signatureToCheck) {
  try {
    // Get the protected headers, payload and signature.
    const [protectedHeaders, payload, signature] = signatureToCheck.split(
      '.',
      3
    );
    // If the signature was in the jws payload then it's not right.
    assert(
      payload === '',
      'Expected detached payload, but payload was provided in the JWS'
    );
    // Create a JSON-Serialised JWS using the expected payload (from the HTTP Request Body)

    const flattened = {
      protected: protectedHeaders,
      payload: expectedPayload,
      signature
    };
    // Verify the re-constructed JWS Signature.
    return jose.JWS.verify(flattened, keystore, joseOpts);
  } catch (error) {
    console.log('failure to verify');
    console.error(error);
    return Promise.reject(error);
  }
}
module.exports.validateSignature = validateSignature;

async function getKeystore(keystoreUrl) {
  return new Promise((resolve, reject) => {
    request(keystoreUrl, { json: true }, async (error, res, body) => {
      if (error) {
        console.error('Unable to fetch keystore url: ', error);
        return reject(error);
      }
      try {
        const keys = body.keys;
        const keystore = jose.JWKS.asKeyStore({ keys });
        console.log({ keystore });
        return resolve(keystore);
      } catch (error) {
        console.log('failure to load .well-known', error);
        return reject(error);
      }
    });
  });
}
