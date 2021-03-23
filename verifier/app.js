// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Verifiable Credentials Verifier Sample

////////////// Node packages
var http = require('http');
var fs = require('fs');
var path = require('path');
var express = require('express')
var session = require('express-session')
var bodyParser = require('body-parser')
var base64url = require('base64url')
var secureRandom = require('secure-random');
var buffer = require('buffer/').Buffer;

//////////////// Verifiable Credential SDK
var { ClientSecretCredential } = require('@azure/identity');
var { CryptoBuilder, 
      RequestorBuilder, 
      ValidatorBuilder,
      KeyReference,
      KeyUse,
      ManagedHttpResolver
    } = require('verifiablecredentials-verification-sdk-typescript');

/////////// Verifier's client details
const client = {
  client_name: 'Sample Verifier',
  logo_uri: 'https://storagebeta.blob.core.windows.net/static/ninja-icon.png',
  tos_uri: 'https://www.microsoft.com/servicesagreement',
  client_purpose: 'To check if you know how to use verifiable credentials.'
}

////////// Verifier's DID configuration values
const config = require('./didconfig.json')
if (!config.did) {
  throw new Error('Make sure you run the DID generation script before starting the server.')
}

////////// Load the VC SDK with the verifier's DID and Key Vault details
const kvCredentials = new ClientSecretCredential(config.azTenantId, config.azClientId, config.azClientSecret);
const signingKeyReference = new KeyReference(config.kvSigningKeyId, 'key');
const recoveryKeyReference = new KeyReference(config.kvRecoveryKeyId, 'key');
const updateKeyReference = new KeyReference(config.kvUpdateKeyId, 'key');

var crypto = new CryptoBuilder()
    .useSigningKeyReference(signingKeyReference)
    .useRecoveryKeyReference(recoveryKeyReference)
    .useUpdateKeyReference(updateKeyReference)
    .useKeyVault(kvCredentials, config.kvVaultUri)
    .useDid(config.did)
    .build();

/////////// Set the expected values for the Verifiable Credential

/*
  const credentialType = 'socure';
  const issuerDid = ['did:ion:EiD_wQgizr8NxoXoaJ71a_qoJ3uaNfoOx-N8dOvDe_yYbg?-ion-initial-state=eyJkZWx0YV9oYXNoIjoiRWlEaS1PSy1WSTk3b1lZUTFrUFBUQUlzQjVkNDJlSm9VOWpaRHBJOENkUGFzQSIsInJlY292ZXJ5X2NvbW1pdG1lbnQiOiJFaURNeVRjQ2thUnliSDJvbFpBa2lGV3lBVENOeEd5Um55YWxUd2g4Y0pKS1dRIn0.eyJ1cGRhdGVfY29tbWl0bWVudCI6IkVpREd3VFJWb2RXN3hwcFE1X3U0emUwbTNYTTFnTlpqY2NNek9GRERrQkJHemciLCJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljX2tleXMiOlt7ImlkIjoic2lnXzgwNzliNTIyIiwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6InNlY3AyNTZrMSIsIngiOiJBZ1RyZEVOcFVqWFpnVVhWamd3ZUlza0ZPdjR0M3gwNDdwelF1bENleEs0IiwieSI6IlpiUmk4QUFUUDVkSzhBZ3MyT3BDVU5EdE16ODQ4YUlNWW1ZYU9seFowcHcifSwicHVycG9zZSI6WyJhdXRoIiwiZ2VuZXJhbCJdfV19fV19'];
  const credential = 'https://portableidentitycards.azure-api.net/v1.0/72b666a1-cc97-4df7-9466-d230923fa3ce/portableIdentities/contracts/socure';
*/

const credentialType = 'AccessAmerica';
const issuerDid = ['did:ion:EiDIyW-TteXeZ_FwW2gVkleUnqyf_LQUUcqLopiP4h8Vgw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWdfMDNkZTJhZDQiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoiRjZBTDVYWFVxQUowRzB6QzVHYXdEMUg4Rzh6OUY3ZFk5MWgwdFVTUzh5YyIsInkiOiJyYWllbWVTOUhvdS14cmFrRzJoU2lGcTNxNFVpOHhlVDktamN'];
const credential = 'credential: https://beta.did.msidentity.com/v1.0/58b6b846-9cc7-4226-af35-5816c2f9336c/verifiableCredential/contracts/AccessAmericaTest';

//////////// Main Express server function
// Note: You'll want to update port values for your setup.
const app = express()
var port = process.env.PORT || 8082;

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

app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Authorization, Origin, X-Requested-With, Content-Type, Accept");
  next();
});

/*
// Serve index.html as the home page
app.get('/', function (req, res) { 
  res.sendFile('public/index.html', {root: __dirname})
})
*/

// echo function so you can test deployment
app.get("/echo",
    function (req, res) {
        res.status(200).json({
            'date': new Date().toISOString(),
            'api': "vc-verifier-api/echo",
            'ipaddr': req.connection.remoteAddress,
            'x-forwarded-for': req.headers['x-forwarded-for'],
            'issuerDid': issuerDid,
            'credentialType': credentialType,
            'client_purpose': client.client_purpose
            });
    }
);

// Generate an presentation request, cache it on the server,
// and return a reference to the issuance request. The reference
// will be displayed to the user on the client side as a QR code.
app.get('/presentation-request', async (req, res) => {
  console.log( "/presentation-request");
  console.log(req.hostname);
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
  console.log( "/presentation-request - " + presentationRequestReference);

  res.status(200).json({
    'id': req.session.id, 
    "link": presentationRequestReference
    });
})


// When the QR code is scanned, Authenticator will dereference the
// presentation request to this URL. This route simply returns the cached
// presentation request to Authenticator.
app.get('/presentation-request.jwt', async (req, res) => {
  console.log( "/presentation-request.jwt - req.query.id=" + req.query.id);
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

  console.log( "/presentation-response");

  var id = req.body.state; // the req.session.id from /presentation-request. We use it to find what session what just auth'd

  // Set up the Verifiable Credentials SDK to validate all signatures
  // and claims in the credential presentation.
  const clientId = `https://${req.hostname}/presentation-response`

  // TEMPORARY OVERRIDE OF THE RESOLVER
  const didResolver = new ManagedHttpResolver('https://beta.discover.did.msidentity.com/1.0/identifiers/');

  // Validate the credential presentation and extract the credential's attributes.
  // If this check succeeds, the user is a Verified Credential Ninja.
  // Log a message to the console indicating successful verification of the credential.
  const validator = new ValidatorBuilder(crypto)
    .useTrustedIssuersForVerifiableCredentials({[credentialType]: issuerDid})
    .useAudienceUrl(clientId)
    .useResolver(didResolver)
    .enableFeatureVerifiedCredentialsStatusCheck(false)
    .build();

  const token = req.body.id_token;
  const validationResponse = await validator.validate(req.body.id_token);
  
  if (!validationResponse.result) {
      console.error(`Validation failed: ${validationResponse.detailedError}`);
      return res.send()
  }

  console.log( "\nid_token=" + token );
  var verifiedCredential = validationResponse.validationResult.verifiableCredentials[credentialType].decodedToken;
  console.log(`${verifiedCredential.vc.credentialSubject.firstName} ${verifiedCredential.vc.credentialSubject.lastName} is a Verified Credential Ninja!`);

  sessionStore.get( id, (error, session) => {
    session.verifiedCredential = verifiedCredential;
    sessionStore.set( id, session, (error) => {
      res.send();
    });
  })

  // Store the successful presentation in session storage
  /*
  sessionStore.get(req.body.state, (error, session) => {

    session.verifiedCredential = verifiedCredential;
    sessionStore.set(req.body.state, session, (error) => {
      res.send();
    });
  })
  */
})


// Checks to see if the server received a successful presentation
// of a Verified Credential Ninja card. Updates the browser UI with
// a successful message if the user is a verified ninja.
app.get('/presentation-response', async (req, res) => {
  var id = req.query.id;
  // If a credential has been received, display the contents in the browser
  sessionStore.get( id, (error, session) => {
    var credentialsVerified = false;
    var givenName = null;
    var surName = null;
    if (session && session.verifiedCredential) {
      console.log( "/presentation-response - has VC " + id);
      console.log(session.verifiedCredential);
      givenName = session.verifiedCredential.vc.credentialSubject.firstName;
      surName = session.verifiedCredential.vc.credentialSubject.lastName;
      credentialsVerified = true;
    } else {
      console.log( "/presentation-response - no VC " + id);
    }
    res.status(200).json({
      'id': id, 
      'credentialsVerified': credentialsVerified,
      'credentialType': credentialType,
      'displayName': `${givenName} ${surName}`,
      'givenName': givenName,
      'surName': surName
      });   
  })

})

function replaceAll(val, from, to) {
  while( val.indexOf(from) >= 0 ) {
    val = val.replace(from,to);
  }
  return val;
}
// same as above but for B2C where we return 409 Conflict if Auth Result isn't OK
var parserJson = bodyParser.json();
app.post('/presentation-response-b2c', parserJson, async (req, res) => {
  var id = req.body.id;
  // If a credential has been received, display the contents in the browser
  sessionStore.get( id, (error, session) => {
    if (session && session.verifiedCredential) {
      var key = replaceAll( session.verifiedCredential.sub.split("?")[0], ":", "." );
      var key64 = buffer.from(key).toString('base64');
      res.status(200).json({
        'id': id, 
        'credentialsVerified': true,
        'credentialType': credentialType,
        'displayName': `${session.verifiedCredential.vc.credentialSubject.firstName} ${session.verifiedCredential.vc.credentialSubject.lastName}`,
        'givenName': session.verifiedCredential.vc.credentialSubject.firstName,
        'surName': session.verifiedCredential.vc.credentialSubject.lastName,
        'iss': session.verifiedCredential.iss,    // who issued this VC?
        'sub': session.verifiedCredential.sub,    // who are you?
//        'key': `${session.verifiedCredential.sub.split("?")[0]}@${session.verifiedCredential.iss.split("?")[0]}`
        'key': key,
        'key64': key64,
        'jti': session.verifiedCredential.jti 
        });   
    } else {
      res.status(409).json({
        'version': '1.0.0', 
        'status': 400,
        'userMessage': 'Verifiable Credentials not authenticated'
        });   
    }
  })

})

// start server
app.listen(port, () => console.log(`Example app listening on port ${port}!`))
