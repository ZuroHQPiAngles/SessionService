package org.piangles.backbone.services.session.jwt;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.codehaus.jettison.json.JSONObject;
import org.piangles.backbone.services.Locator;
import org.piangles.backbone.services.logging.LoggingService;
import org.piangles.backbone.services.session.SessionManagementException;

import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class JWTUtils {

    private static final long ACCESS_TOKEN_EXPIRATION_TIME = 5000; // 5 seconds
    private static final long REFRESH_TOKEN_EXPIRATION_TIME = 1000 * 60 * 15; // 15 minutes

    private static final String ENCRYPTION_KEY = "avalara123"; // Symmetric encryption key
    private static final String SECRET_KEY = "avalara321";  // Key for signing JWT header (used in signing the JWT)

    private final LoggingService logger = Locator.getInstance().getLoggingService();

    public String generateJwe(String userId, String sessionId) throws SessionManagementException {
        try
        {
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(userId)
                    .claim("iat", System.currentTimeMillis())
                    .claim("exp", System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION_TIME)
                    .claim("sid", sessionId)
                    .build();

            logger.info("GENERATE JWE:: Created ClaimSet");

            SecureRandom secureRandom = new SecureRandom();
            byte[] kek = new byte[32];
            secureRandom.nextBytes(kek);

            SecretKeySpec secretKey = new SecretKeySpec(kek, "AES");

            JWEHeader header = new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256GCM);

            EncryptedJWT encryptedJWT = new EncryptedJWT(header, claimsSet);

            encryptedJWT.encrypt(new AESEncrypter(secretKey));

            return encryptedJWT.serialize();
        }
        catch (Exception e)
        {
            logger.error("Error while generating JWT: " + e.getMessage());
            throw new SessionManagementException("Error generating access token", e);
        }

    }

    private static String decryptJwe(String jwe) throws SessionManagementException {
        try
        {
            EncryptedJWT encryptedJWT = EncryptedJWT.parse(jwe);

            encryptedJWT.decrypt(new AESDecrypter(new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES")));

            return encryptedJWT.getPayload().toString();
        }
        catch (Exception e)
        {
            throw new SessionManagementException("Error while decrypting jwe token", e);
        }

    }

    public Triple<String,String, Boolean> authenticateJwe(String jwe) throws SessionManagementException {
        try {
            String decryptedPayload = decryptJwe(jwe);
            JSONObject payload = new JSONObject(decryptedPayload);

            long expiration = payload.getLong("exp");
            if (expiration < System.currentTimeMillis()) {
                logger.info("JWE has expired!");
                return Triple.of(null, null,false);
            }

            String userId = payload.getString("sub");
            String sessionId = payload.getString("sid");

            if(StringUtils.isAnyEmpty(userId, sessionId)) {
                logger.info("Not found userId or sessionId in JWE!");
                return Triple.of(null, null,false);
            }

            logger.info("JWE authenticated for userId: " + userId + ", sessionId: " + sessionId);
            return Triple.of(userId, sessionId,true);
        }
        catch (Exception e)
        {
            throw new SessionManagementException("Error while authenticating jwe token", e);
        }
    }

    public String refreshAccessToken(String refreshToken) throws SessionManagementException {
        final Pair<String, String> claims = validateRefreshToken(refreshToken);
        if (StringUtils.isAnyEmpty(claims.getLeft(), claims.getRight())) {
            throw new SessionManagementException("Unable to extract sessionId/UserId from refresh token");
        }

        try
        {
            return generateJwe(claims.getLeft(), claims.getRight());
        }
        catch (Exception e)
        {
            throw new SessionManagementException("Unable to refresh access token", e);
        }
    }

    public String generateRefreshToken(String userId, String sessionId) throws SessionManagementException {
        try
        {
            SecureRandom secureRandom = new SecureRandom();
            byte[] kek = new byte[32];
            secureRandom.nextBytes(kek);
            JWSSigner signer = new MACSigner(kek);
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(userId)
                    .claim("sid", sessionId)
                    .claim("iat", System.currentTimeMillis())
                    .claim("exp", System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION_TIME)
                    .build();

            logger.info("GENERATE RefreshToken:: Created ClaimSet");

            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
            signedJWT.sign(signer);

            return signedJWT.serialize();
        }
        catch (Exception e)
        {
            logger.error("Error while generating refresh token: " + e.getMessage());
            throw new SessionManagementException("Error generating refresh token", e);
        }
    }

    private static Pair<String, String> validateRefreshToken(String refreshToken) throws SessionManagementException {
        try {
            SignedJWT signedJWT = SignedJWT.parse(refreshToken);

            JWSVerifier verifier = new MACVerifier(SECRET_KEY.getBytes());
            if (!signedJWT.verify(verifier)) {
                throw new SessionManagementException("Invalid refresh token signature");
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet.getExpirationTime().getTime() < System.currentTimeMillis()) {
                throw new SessionManagementException("Refresh Token expired");
            }

            return Pair.of(claimsSet.getSubject(), (String) claimsSet.getClaim("sid"));
        }
        catch (Exception e) {
            throw new SessionManagementException("Unable to validate refresh token", e);
        }
    }
}
