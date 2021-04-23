// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Verifiable Credentials Verifier Sample

////////////// Node packages
var express = require('express')
var session = require('express-session')
var bodyParser = require('body-parser')
var base64url = require('base64url')
var secureRandom = require('secure-random');

const dotenv = require('dotenv');
dotenv.config(); // loads environment variables

//////////////// Verifiable Credential SDK
var { ClientSecretCredential } = require('@azure/identity');
var { CryptoBuilder, 
      RequestorBuilder, 
      ValidatorBuilder,
      KeyReference
    } = require('verifiablecredentials-verification-sdk-typescript');

/////////// Verifiers client details
const client = {
  client_name: 'Access America Verifier',
  logo_uri: 'https://ccuspocverifier.blob.core.windows.net/verifier-static/icon.png',
  tos_uri: 'https://www.microsoft.com/servicesagreement',
  client_purpose: 'Test Access America credential verification.'
}

////////// Verifiers DID configuration values
const config = require('./didconfig.json')
if (!config.did) {
  throw new Error('Make sure you run the DID generation script before starting the server.')
}

////////// Load the VC SDK with the Issuing Service's DID and Key Vault details
var verifierAzClientSecret = process.env.VERIFIER_AZ_CLIENT_SECRET;
//console.log(`verifierAzClientSecret: ${verifierAzClientSecret}`);
const kvCredentials = new ClientSecretCredential(config.azTenantId, config.azClientId, verifierAzClientSecret);
const signingKeyReference = new KeyReference(config.kvSigningKeyId, 'key', config.kvRemoteSigningKeyId);

/////////// Set the expected values for the Verifiable Credential
const credential = 'https://beta.did.msidentity.com/v1.0/58b6b846-9cc7-4226-af35-5816c2f9336c/verifiableCredential/contracts/AccessAmericaTest';
const credentialType = 'AccessAmerica';
const issuerDid = ['did:ion:EiDIyW-TteXeZ_FwW2gVkleUnqyf_LQUUcqLopiP4h8Vgw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWdfMDNkZTJhZDQiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoiRjZBTDVYWFVxQUowRzB6QzVHYXdEMUg4Rzh6OUY3ZFk5MWgwdFVTUzh5YyIsInkiOiJyYWllbWVTOUhvdS14cmFrRzJoU2lGcTNxNFVpOHhlVDktamNjel9VaHNvIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIiwiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VzIjpbeyJpZCI6ImxpbmtlZGRvbWFpbnMiLCJzZXJ2aWNlRW5kcG9pbnQiOnsib3JpZ2lucyI6WyJodHRwczovL2FjY2Vzc2FtZXJpY2EudXMvIl19LCJ0eXBlIjoiTGlua2VkRG9tYWlucyJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpRFBNYW5QRDFpMmRiWDk4TXE4a2lBaDB4M0NoU1VQd1V3a1FwNUNqYWttbGcifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNvbVF3ZktRVWJRT1BReC1mMHFxLVF0d3RPYTM4alBXUmxmcTktamNXWGpnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlBSmpJWWp4MnlJQ2xXalpQOWRNaDVlcWswQ294eFBMWGhPaUJUY3JTdWNoQSJ9fQ'];

var crypto = new CryptoBuilder()
    .useSigningKeyReference(signingKeyReference)
    .useKeyVault(kvCredentials, config.kvVaultUri)
    .useDid(config.did)
    .build();


//////////// Main Express server function
// Note: You'll want to update port values for your setup.
const app = express()
const port = process.env.PORT || 8082;

// Serve static files out of the /public directory
app.use(express.static('public'))

// Set up a simple server side session store.
// The session store will briefly cache presentation requests
// to facilitate QR code scanning, and store presentation responses
// so they can be retrieved by the browser.
var sessionStore = new session.MemoryStore();
app.use(session({
  secret: 'cookie-secret-key',
  resave: false,
  saveUninitialized: true,
  store: sessionStore
}))

// echo function so you can test deployment
app.get("/echo",
    function (req, res) {
        res.status(200).json({
            'date': new Date().toISOString(),
            'api': req.protocol + '://' + req.hostname + req.originalUrl,
            'Host': req.hostname,
            'x-forwarded-for': req.headers['x-forwarded-for'],
            'x-original-host': req.headers['x-original-host'],
            'issuerDid': issuerDid,
            'credentialType': credentialType,
            'client_purpose': client.client_purpose
            });
    }
);

// Enable CORS in Azure
// https://docs.microsoft.com/en-us/azure/active-directory-b2c/customize-ui-with-html?pivots=b2c-user-flow#2-create-an-azure-blob-storage-account

// app.use(function (req, res, next) {
//   res.header("Access-Control-Allow-Origin", "*");
//   res.header("Access-Control-Allow-Headers", "Authorization, Origin, X-Requested-With, Content-Type, Accept");
//   next();
// });

// Serve index.html as the home page
  app.get('/', function (req, res) { 
    res.sendFile('public/index.html', {root: __dirname})
  })

// Generate an presentation request, cache it on the server,
// and return a reference to the issuance reqeust. The reference
// will be displayed to the user on the client side as a QR code.
app.get('/presentation-request', async (req, res) => {

  // Construct a request to issue a verifiable credential 
  // using the verifiable credential issuer service
  state = req.session.id;
  const nonce = base64url.encode(Buffer.from(secureRandom.randomUint8Array(10)));
  const clientId = `https://${req.hostname}/presentation-response`;

  const requestBuilder = new RequestorBuilder({
    clientName: client.client_name,
    clientId: clientId,
    redirectUri: clientId,
    logoUri: client.logo_uri,
    tosUri: client.tos_uri,
    client_purpose: client.client_purpose,
    presentationDefinition: {
      input_descriptors: [{
          id:"ninja",
          schema: {
              uri: [credentialType],
          },
          issuance: [{
              manifest: credential
          }]
      }]
  }
},  crypto)
    .useNonce(nonce)
    .useState(state);

  // Cache the issue request on the server
  req.session.presentationRequest = await requestBuilder.build().create();
  
  // Return a reference to the presentation request that can be encoded as a QR code
  var requestUri = encodeURIComponent(`https://${req.hostname}/presentation-request.jwt?id=${req.session.id}`);
  var presentationRequestReference = 'openid://vc/?request_uri=' + requestUri;
  res.send(presentationRequestReference);

})


// When the QR code is scanned, Authenticator will dereference the
// presentation request to this URL. This route simply returns the cached
// presentation request to Authenticator.
app.get('/presentation-request.jwt', async (req, res) => {

  // Look up the issue reqeust by session ID
  sessionStore.get(req.query.id, (error, session) => {
    res.send(session.presentationRequest.request);
  })

})


// Once the user approves the presentation request,
// Authenticator will present the credential back to this server
// at this URL. We can verify the credential and extract its contents
// to verify the user is a Verified Credential Ninja.
var parser = bodyParser.urlencoded({ extended: false });
app.post('/presentation-response', parser, async (req, res) => {

  // Set up the Verifiable Credentials SDK to validate all signatures
  // and claims in the credential presentation.
  const clientId = `https://${req.hostname}/presentation-response`

  // Validate the credential presentation and extract the credential's attributes.
  // If this check succeeds, the user is a Verified Credential Ninja.
  // Log a message to the console indicating successful verification of the credential.

  const validator = new ValidatorBuilder(crypto)
    .useTrustedIssuersForVerifiableCredentials({[credentialType]: issuerDid})
    .useAudienceUrl(clientId)
    .build();

  const token = req.body.id_token;
  const validationResponse = await validator.validate(req.body.id_token);
  
  if (!validationResponse.result) {
      console.error(`Validation failed: ${validationResponse.detailedError}`);
      return res.send()
  }

  var verifiedCredential = validationResponse.validationResult.verifiableCredentials[credentialType].decodedToken;
  console.log(`${verifiedCredential.vc.credentialSubject.firstName} ${verifiedCredential.vc.credentialSubject.lastName} is a Verified Credential Ninja!`);

  // Store the successful presentation in session storage
  sessionStore.get(req.body.state, (error, session) => {

    session.verifiedCredential = verifiedCredential;
    sessionStore.set(req.body.state, session, (error) => {
      res.send();
    });
  })
})


// Checks to see if the server received a successful presentation
// of a Verified Credential Ninja card. Updates the browser UI with
// a successful message if the user is a verified ninja.
app.get('/presentation-response', async (req, res) => {

  // If a credential has been received, display the contents in the browser
  if (req.session.verifiedCredential) {

    presentedCredential = req.session.verifiedCredential;
    req.session.verifiedCredential = null;
    return res.send(`Congratulations, ${presentedCredential.vc.credentialSubject.firstName} ${presentedCredential.vc.credentialSubject.lastName} is a Verified Credential Ninja!`)  
  }

  // If no credential has been received, just display an empty message
  res.send('')

})

// start server
app.listen(port, () => console.log(`Example app listening on port ${port}!`))