package edu.ucdavis.library.jetty;

import java.io.UnsupportedEncodingException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JwtParser {
	
	private JWTVerifier verifier;
	
	// TODO: check token expiration
	public void init(String secret, String issuer) throws IllegalArgumentException, UnsupportedEncodingException {
		Algorithm algorithm = Algorithm.HMAC256(secret);
	    verifier = JWT.require(algorithm)
	        .withIssuer(issuer)
	        .build();
	}
	
	public DecodedJWT verify(String token) {
	    return verifier.verify(token);
	}
}
