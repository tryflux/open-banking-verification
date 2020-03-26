const jose = require('jose');
const request = require('request');

const keystoreUrl =
  'https://api.development.env.tryflux.com/auth/.well-known/jwks.json';
const sigToCheck =
  'eyJraWQiOiJPaTdZei1oaElGRExnOVJtMFZwZFBwR2pOOFdIcWVGc0JnXzdtN05JYmpJPSIsImFsZyI6IlBTMjU2IiwidHlwIjoiSk9TRSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il0sImN0eSI6ImFwcGxpY2F0aW9uL2pzb24ifQ..kiqa36x-mXwx4QboVI7RNZfMTA5djGIv8k7JbP7-9vctvmDRbOrnd0KKysXzqMxXyecXOMEpAoIPwChvRFdMpDtosKtqYoG75PoBthzd9JILRmSVLts-ZRVsBqKRMaGenKwA35F-rL8LbSyW7hJ8spfjXN0kRX5u6wyL_cQSE3JAS7sXi4kOZEye-I1Rn_tp0GVeCfgmm6Rya0w3Fwp15cr0tOIHDJL0OV2p_BDDvs5VRuefLvMe36pMWMeuCvBvgqOhPo7-Nk1L1aqqYKFI_ZzVinHJGUGSh1ns5DFrImeM2muTE9g8feE6f_NkL5Uv6Plod2tKfLDSRHnW4r6ipA';

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
        crit: ['b64', 'typ', 'kid', 'b64', 'cty', 'alg', 'crit']
      };
      let result = null;
      try {
        result = await jose.JWS.verify(sigToCheck, keystore, opts);
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
