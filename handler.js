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

const auth = require('./auth');
const { config } = require('./config');
const configMappings = require('./configMappings')

module.exports.auth = (event, context, callback) => {
  const request = event.Records[0].cf.request;
  const headers = request.headers;

  // console.log(headers);
  
  try {
    if (headers.authorization === undefined) {
      throw new Error('No Authorization header defined');
    }

    let token = headers.authorization[0].value;
    // console.log('YOUR TOKEN IS ' + token);

    if (!token.startsWith("Bearer")) {
      throw new Error('Authorization header must begin with "Bearer"');
    }

    token = token.substring(7)   // remove 'Bearer'

    const user = auth.validateJwt(token);
    const DEFAULT_GROUP = '_default';
    let group = DEFAULT_GROUP;

    // console.log(JSON.stringify(user));

    if (user.groups !== undefined && user.groups.length > 0) {
      if (user.groups.length > 1) {
        throw new Error("User cannot belong to multiple groups")
      } else {
        group =user.groups[0]
      }
    }

    let apiKey = null;
        
    if (group in configMappings.mappings) {
      apiKey = configMappings.mappings[group]
    } else {
      if (group == DEFAULT_GROUP) {
        throw new Error('User has no Cognito group and no _default is defined in configuration mappings');
      } else {
        throw new Error('Unmapped Cognito group: '+ group)
      }      
    }    
    
    // console.log("Setting x-api-key: "+ apiKey);

    headers['x-api-key'] = [{ key: 'x-api-key', value: apiKey }];
    delete request.headers.authorization  // needed, otherwise 2 users of the same group will not benefit of cache

    return callback(null, request);
  } catch (error) {
    console.log('Error: '+ error)

    const response = {      
      status: '401',
      statusDescription: error
    };
  
    return callback(null, response);
  }
};

