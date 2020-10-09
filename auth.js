/*
The MIT License (MIT)

Copyright (c) 2019-2020, Andrew Paul Rodriguez

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

'use strict';

const config = require('./config.js');
const jsonwebtoken = require('jsonwebtoken');

/**
 * Returns a user object if the token is valid
 * @param {string} jwtToken
 * @return { userName: <claim.username>, clientId: <claim.client_id>, groups: <claim['cognito:groups']>};
 */
module.exports.validateJwt = function (jwtToken) {
    const keys = config.config.keys;
    const cognitoIssuer = config.config.cognitoIssuer;

    let result = null;

    // console.log(`user claim verify invoked`);
    const tokenSections = (jwtToken || '').split('.');
    if (tokenSections.length < 2) {
        throw new Error('requested token is invalid');
    }
    const headerJSON = Buffer.from(tokenSections[0], 'base64').toString('utf8');
    const header = JSON.parse(headerJSON);
    // console.log("KID: " + header.kid);
    let pem = null;

    for (let i = 0; i < keys.length; i++) {
        if (keys[i].kid == header.kid) {
            pem = keys[i].pem
            break
        }
    }

    if (pem == null) {
        throw new Error('kid not found, check your configuration: ' + header.kid);
    }

    // console.log(JSON.stringify(pem));

    const claim = jsonwebtoken.verify(jwtToken, pem);
    const currentSeconds = Math.floor((new Date()).valueOf() / 1000);

    if (currentSeconds > claim.exp || currentSeconds < claim.auth_time) {
        throw new Error('claim is expired or invalid');
    }

    if (claim.iss !== cognitoIssuer) {
        throw new Error('claim issuer is invalid: ' + claim.iss);
    }
    if (claim.token_use !== 'access') {
        throw new Error('claim use is not access');
    }
    // console.log(`claim confirmed for ${claim.username}`);
    result = { userName: claim.username, clientId: claim.client_id, groups: claim['cognito:groups']};

    return result
}

