# hive-auth-client
Event based client for Hive Auth Services

## Installation
```
npm install hive-auth-client
```

## Usage
### Connection
```
import HasClient from 'hive-auth-client';
import { PublicKey, Signature, hash } from '@hiveio/hive-js/lib/auth/ecc';

const APP_META = {
    name: 'Hive Blog',
    description: 'Hive Blog',
    icon: 'https://hive.blog/images/hive-blog-logo.png',
};

const auth = {
    username: undefined,
    token: undefined,
    expire: undefined,
    key: undefined,
};

const client = new HasClient('hive-auth.arcange.eu', '', true);
```

HAS Client will auto connect the websocket when attempting to send a message.

## Authentication + Challenge
```
const verifyChallenge = (challenge, data) => {
    // Validate signature against account public key
    const sig = Signature.fromHex(data.challenge);
    const buf = hash.sha256(challenge, null, 0);
    return sig.verifyHash(buf, PublicKey.fromString(data.pubkey));
};

auth.username = username;
const challenge = JSON.stringify({
    login: auth.username,
    ts: Date.now()
});

const challengeData = {
    key_type: 'posting',
    challenge,
};

client.addEventHandler('AuthPending', (message) => {
    const {
        account, expire, key, uuid,
    } = message;
    const now = new Date().getTime();
    if (now < expire) {
        const authPayload = {
            uuid,
            account,
            key,
            host: 'wss://hive-auth.arcange.eu',
        };

        auth.key = key;

        const authUri = `has://auth_req/${btoa(JSON.stringify(authPayload))}`;

        /* Your logic for generating the QR code and displaying it */
    } else {
        /* Your logic to handle expiry*/
    }
});

client.addEventHandler('AuthSuccess', (message) => {
    const {
        data, uuid, authData,
    } = message;
    const { expire, token, challenge: challengeResponse } = data;

    auth.token = authData.token;
    auth.key = authData.key;
    auth.expire = authData.expire;
    
    const verified = verifyChallenge(challenge, challengeResponse);
    if (verified) {
        /* Handle success */
    } else {
        /* Handle failure */
    }
});

client.addEventHandler('AuthFailure', (message) => {
    /* Handle failure */
});

client.addEventHandler('RequestExpired', (error) => {
    /* Handle expiry */
});

client.addEventHandler('AttachFailure', (error) => {
   /* Handle failure */
});
```

## Broadcasting a transaction
```
client.addEventHandler('SignPending', () => {
    /* Show instructions to user to use supported wallet app to approve broadcast */ 
});

client.addEventHandler('SignSuccess', (message) => {
    /* Handle success */
});

client.addEventHandler('SignFailure', (error) => {
    /* Handle failure */
});

client.addEventHandler('SignError', (error) => {
    /* Handle error */
});

client.broadcast(auth, type, operations);
```

## Signing a challenge
```
client.addEventHandler('ChallengePending', () => {
    /* Show instructions to user to use supported wallet app to approve broadcast */ 
});

client.addEventHandler('ChallengeSuccess', (message) => {
    /* Handle success */
});

client.addEventHandler('ChallengeFailure', (error) => {
    /* Handle failure */
});

client.addEventHandler('ChallengeError', (error) => {
    /* Handle error */
});

const challenge = JSON.stringify({
    login: auth.username,
    ts: Date.now()
});

const challengeData = {
    key_type: 'posting',
    challenge,
};

client.challenge(authData, challengeData);
```