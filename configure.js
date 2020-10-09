const configGen = require('./configGen')

// Usage: node configure <cognitoPoolId> [<region>]
// es. node configure us-west-1_ibXXXjA1w
// es. node configure us-east-1_ibXXXjA1w us-east-1
const cognitoPoolId = process.argv[2]
let region = 'us-east-1'

console.log(cognitoPoolId);

if (process.argv.length == 4) {
    region = process.argv[3]
}

configGen.generate(cognitoPoolId, region)



