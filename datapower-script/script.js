var jose = require('jose');
var jwt = require('jwt');
var hm = require('header-metadata');

// Configured DataPower Crypto Key: issuer's RSA private key.
var signingKey = 'jws-sign-key';

// Configured DataPower Crypto Certificate: API's RSA public certificate.
var encryptionCertificate = 'jwe-encrypt-cert';

session.input.readAsJSON(function (readError, json) {
    if (readError || json === undefined) {
        session.reject('Unable to read request body as JSON');
        return;
    }

    try {
        var now = Math.floor(Date.now() / 1000);

        var claims = {
            iss: 'https://fxnaranjo.example',
            aud: 'secure-api',
            iat: now,
             exp: now + (360 * 60)
        };

        var jwsHeader = jose.createJWSHeader(signingKey, 'RS256');
        jwsHeader.setProtected('typ', 'JWT');

        var jweHeader = jose.createJWEHeader('A256CBC-HS512');
        jweHeader.setProtected('alg', 'RSA-OAEP-256');
        jweHeader.setProtected('cty', 'JWT');
        jweHeader.setKey(encryptionCertificate);

        new jwt.Encoder(claims)
            .addOperation('sign', jwsHeader)
            .addOperation('encrypt', jweHeader)
            .encode(function (error, encryptedToken) {
                if (error || !encryptedToken) {
                    session.reject('JWT generation failed');
                    return;
                }

                hm.current.set('Authorization', 'Bearer ' + encryptedToken);
                hm.current.set('Content-Type', 'application/x-www-form-urlencoded');
                //hm.current.set('json', json);
                //hm.current.set('claims', JSON.stringify(claims));

                // Forward the JSON body after generating the token.
                  var params = [];

		    Object.keys(json).forEach(function (key) {
			var value = json[key];

			// Skip null/undefined values
			if (value === null || value === undefined) {
			    return;
			}

			// Encode keys and values for form submission
			params.push(
			    encodeURIComponent(key) + "=" +
			    encodeURIComponent(
				typeof value === "object"
				    ? JSON.stringify(value)
				    : String(value)
			    )
			);
		    });

		    var formBody = params.join("&");
		    
                session.output.write(formBody);
            });
    } catch (error) {
        session.reject('Unable to prepare authenticated request');
    }
});
