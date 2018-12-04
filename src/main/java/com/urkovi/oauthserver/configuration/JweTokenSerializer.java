package com.urkovi.oauthserver.configuration;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Map;

public class JweTokenSerializer {
    private KeyPair keyPair;

    public JweTokenSerializer(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public String encode(String payload) {
        try {
            /*
            JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);
            Payload payloadObject = new Payload(payload);

            JWEObject jwe = new JWEObject(header, payloadObject);

            JWEEncrypter encrypter = new RSAEncrypter((RSAPublicKey)keyPair.getPublic());
            */
            RSAKey senderJWK = new RSAKeyGenerator(2048)
                    .keyID("123")
                    .keyUse(KeyUse.SIGNATURE)
                    .generate();
            RSAKey senderPublicJWK = senderJWK.toPublicJWK();
            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(senderJWK.getKeyID()).build(),
                    new JWTClaimsSet.Builder()
                            .subject("alice")
                            .issueTime(new Date())
                            .issuer("https://localhost")
                            .build());

            // Sign the JWT
            signedJWT.sign(new RSASSASigner(senderJWK));

            // Create JWE object with signed JWT as payload
            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                            .contentType("JWT") // required to indicate nested JWT
                            .build(),
                    new Payload(signedJWT));

// Encrypt with the recipient's public key


            return jweObject.serialize();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Map<String, Object> decode(String content) {
        try {
            JWEObject  jweObject = JWEObject.parse(content);
            JWEDecrypter decrypter = new RSADecrypter(keyPair.getPrivate());

            jweObject.decrypt(decrypter);

            Payload payload = jweObject.getPayload();
            ObjectMapper objectMapper = new ObjectMapper();
            ObjectReader reader = objectMapper.readerFor(Map.class);
            return reader.with(DeserializationFeature.USE_LONG_FOR_INTS)
                    .readValue(payload.toString());

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
}
