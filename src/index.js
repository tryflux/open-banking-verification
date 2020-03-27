const jose = require('jose');
const request = require('request');

const keystoreUrl =
  'https://api.preprod.env.tryflux.com/auth/.well-known/jwks.json';
const sigToCheck =
'eyJhbGciOiJQUzI1NiIsImtpZCI6ImpxTDByOW5JTHN1MVZhU0lDLXlnR2xHWklRV2N6dmgyczJkakpoclFlZDQ9UFMyNTYiLCJ0eXAiOiJKT1NFIiwiYjY0IjpmYWxzZSwiY3JpdCI6WyJiNjQiXSwiY3R5IjoiYXBwbGljYXRpb24vanNvbiJ9..CkvoYVynU3X8EbQHcW2T4gopU3A-my-9-b6ywzuRkWwPfDWwQkoZciHOs__qXyiUtCnaFLxtcs2k6ebaPTNiz3Wq669CNXdj7FKqbc0xFg9dPf2lf_z3-Gq_2lInX24oibn_l1hgD200I7sTQxqIxs-BpcXBgKZ9ww6rI4_Q7XKWXPG3vtvmYqsWHNcoXj9SL8-o5vHuLbHKKucJ1jUIDrRWEtzL7VZvRp2TCfgJkw2YlByQY_l9AI5L0UaFPWT3p3-CUE63aQP9BwmZrroQrPJe6dRefKoEy5ZQUGJC8AuabJXQDDl6Ii13mj8F3FusxEb9aQ8euSbDw4JkbvM1nQ'
const expectedPayload = '{"data":[{"id":"143949bf-424d-46e2-9fa5-770e8bc5f670","attributes":{"id":"143949bf-424d-46e2-9fa5-770e8bc5f670","bankTransactionId":"4494d5fc-8b21-4ffc-81b0-8f4dd63dbd3f","collectionNumber":"1423","total":{"amount":1001,"currency":"GBP"},"transactionDate":"2020-03-27T11:25:52.024Z","merchant":{"name":"-"},"notes":[{"description":{"label":"Not a VAT receipt"}}],"payments":[{"type":"card","lastFour":"1234","authCode":"9e422c","paid":{"amount":1001,"currency":"GBP"}}],"items":[{"description":{"label":"3 Legend Fillet Box Meal"},"quantity":2,"amount":{"amount":102,"currency":"GBP"}}]},"type":"receipt"}]}'
try {
  request(keystoreUrl, { json: true }, async (error, res, body) => {
    if (error) {
      console.error('Unable to fetch keystore url: ', error);
      process.exit(1);
    } else {
      let keystore = null;
      try {
        keystore = await jose.JWKS.asKeyStore(body);
      } catch (error) {
        console.log('failure to load .well-known');
        console.error(error);
        return;
      }
      const opts = {
        crit: ['b64', 'typ', 'kid', 'cty', 'alg', 'crit']
      };
      let result = null;
      try {
        const [protected, payload, signature] = sigToCheck.split(".", 3)
        assert(payload == "", "Expected detached payload")
        
        const flattened = {
          protected,
          payload: expectedPayload,
          signature
        }

        result = await jose.JWS.verify(flattened, keystore, opts);
      } catch (error) {
        console.log('failure to verify');
        console.error(error);
        return;
      }
      console.log('INFO: result=', result);
    }
  });
} catch (error) {
  console.error(error);
}

function assert(condition, message) {
  if(!condition) {
    throw new Error(message)
  }
}