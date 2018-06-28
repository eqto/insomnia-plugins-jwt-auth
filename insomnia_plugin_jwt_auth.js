const crypto = require('crypto');

module.exports.templateTags = [{
    name: 'jwtauth',
    displayName: 'JWT Auth',
    description: 'Generate JWT Authorization',
    args: [
        {
            displayName: 'Payload',
            type: 'string',
            placeholder: 'Payload'
        },
        {
            displayName: 'Secret',
            type: 'string',
            placeholder: 'Secret'
        }
    ],
    run (context, payload, secret) {
        var header = Buffer.from('{"alg": "HS256","typ": "JWT"}').toString('base64')
        header = header.replace(/=+$/, '');
        header = header.replace(/\+/g, '-');
        header = header.replace(/\//g, '_');

        var payload64 = Buffer.from(payload).toString('base64')
        payload64 = payload64.replace(/=+$/, '');
        payload64 = payload64.replace(/\+/g, '-');
        payload64 = payload64.replace(/\//g, '_');

        const hash = crypto.createHmac('sha256', secret);
        signature = hash.update(header + '.' + payload64).digest('base64');
        signature = signature.replace(/=+$/, '');
        signature = signature.replace(/\+/g, '-');
        signature = signature.replace(/\//g, '_');
    
        return header + '.' + payload64 + '.' + signature;
    }
}];
