package com.urkovi.oauthserver.configuration;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.security.authentication.BadCredentialsException;

import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


public class CustomJwtService {
    public static final String IAT = "iat";
    private DirectEncrypter encrypter;
    private JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
    private ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor;

    public CustomJwtService(String secret) throws KeyLengthException {

        byte[] secretKey = secret.getBytes();
        encrypter = new DirectEncrypter(secretKey);
        jwtProcessor = new DefaultJWTProcessor<>();

        // The JWE key source
        JWKSource<SimpleSecurityContext> jweKeySource = new ImmutableSecret<>(secretKey);

        // Configure a key selector to handle the decryption phase
        JWEKeySelector<SimpleSecurityContext> jweKeySelector =
                new JWEDecryptionKeySelector<>(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256, jweKeySource);

        jwtProcessor.setJWEKeySelector(jweKeySelector);
    }
    /**
     * Creates a token
     */
    public String createToken(String aud, String subject, Long expirationMillis, Map<String, Object> claimMap) {

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

        builder
                //.issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + expirationMillis))
                .audience(aud)
                .subject(subject);


        claimMap.put("iat", new Date());
        claimMap.forEach(builder::claim);

        JWTClaimsSet claims = builder.build();

        Payload payload = new Payload(claims.toJSONObject());

        // Create the JWE object and encrypt it
        JWEObject jweObject = new JWEObject(header, payload);

        try {

            jweObject.encrypt(encrypter);

        } catch (JOSEException e) {

            throw new RuntimeException(e);
        }

        // Serialize to compact JOSE form...
        return jweObject.serialize();
    }

    /**
     * Creates a token
     */
    public String createToken(String audience, String subject, Long expirationMillis) {

        return createToken(audience, subject, expirationMillis, new HashMap<>());
    }

    /**
     * Parses a token
     */
    public JWTClaimsSet parseToken(String token, String audience) throws ParseException {

        try {

            JWTClaimsSet claims = jwtProcessor.process(token, null);
            /*
            LecUtils.ensureCredentials(audience != null &&
                            claims.getAudience().contains(audience),
                    "com.naturalprogrammer.spring.wrong.audience");
*/
            long expirationTime = claims.getExpirationTime().getTime();
            long currentTime = System.currentTimeMillis();
/*
            log.debug("Parsing JWT. Expiration time = " + expirationTime
                    + ". Current time = " + currentTime);

            LecUtils.ensureCredentials(expirationTime >= currentTime,
                    "com.naturalprogrammer.spring.expiredToken");
*/
            return claims;

        } catch (ParseException | BadJOSEException | JOSEException e) {

            throw new BadCredentialsException(e.getMessage());
        }
    }

    /**
     * Parses a token
     */
    public JWTClaimsSet parseToken(String token, String audience, long issuedAfter) throws ParseException {

        JWTClaimsSet claims = parseToken(token, audience);

        //long issueTime = (long) claims.getClaim(LEMON_IAT);
        /*
        LecUtils.ensureCredentials(issueTime >= issuedAfter,
                "com.naturalprogrammer.spring.obsoleteToken");
*/
        return claims;
    }
}
