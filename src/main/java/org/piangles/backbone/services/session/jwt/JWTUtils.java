package org.piangles.backbone.services.session.jwt;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.tuple.Triple;
import org.piangles.backbone.services.Locator;
import org.piangles.backbone.services.logging.LoggingService;
import org.piangles.backbone.services.session.SessionManagementException;

import java.time.Instant;
import java.util.Date;

public class JWTUtils {

    private static final long ACCESS_TOKEN_EXPIRATION_TIME = 5L; // 5 seconds
    private static final long REFRESH_TOKEN_EXPIRATION_TIME = 15 * 60L; // 15 minutes

    private final LoggingService logger;
    private final String secretKey;

    public JWTUtils(String secretKey) {
        this.secretKey = secretKey;
        logger = Locator.getInstance().getLoggingService();
    }

    public String generateAccessToken(String userId, String sessionId) throws SessionManagementException {
        try {
            final JWTClaimsSet claims = buildClaims(userId, sessionId, ACCESS_TOKEN_EXPIRATION_TIME);
            JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
            MACSigner signer = new MACSigner(secretKey.getBytes());
            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (Exception e) {
            final String errMsg = "Error generating access token: " + e.getMessage();
            logger.error(errMsg, e);
            throw new SessionManagementException(errMsg);
        }
    }

    public Triple<String, String, Boolean> authenticateAccessToken(String accessToken) throws SessionManagementException {
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);

            MACVerifier verifier = new MACVerifier(secretKey.getBytes());
            if (!signedJWT.verify(verifier)) {
                logger.error("Invalid access token signature");
                return Triple.of(null, null, false);
            }

            final JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            if (claimsSet.getExpirationTime().getTime() < System.currentTimeMillis())
            {
                logger.error("Access token expired.");
                return Triple.of(null, null, false);
            }
            return Triple.of(claimsSet.getSubject(), claimsSet.getClaimAsString("sid"),  true);
        } catch (Exception e) {
            final String errMsg = "Error parsing access token: " + e.getMessage();
            logger.error(errMsg, e);
            throw new SessionManagementException(errMsg);
        }
    }

    public String generateRefreshToken(String userId, String sessionId) throws SessionManagementException {
        try {
            final JWTClaimsSet claims = buildClaims(userId, sessionId, REFRESH_TOKEN_EXPIRATION_TIME);
            JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
            MACSigner signer = new MACSigner(secretKey.getBytes());
            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (Exception e) {
            final String errMsg = "Error generating refresh token: " + e.getMessage();
            logger.error(errMsg, e);
            throw new SessionManagementException(errMsg);
        }
    }

    public String refreshAccessToken(String refreshToken) throws SessionManagementException {
        try {
            JWTClaimsSet claims = parseRefreshToken(refreshToken);
            String userId = claims.getSubject();
            String sessionId = claims.getStringClaim("sid");
            return generateAccessToken(userId, sessionId);
        } catch (Exception e) {
            final String errMsg = "Error while refreshing access token: " + e.getMessage();
            logger.error(errMsg, e);
            throw new SessionManagementException(errMsg);
        }
    }

    private JWTClaimsSet parseRefreshToken(String refreshToken) throws SessionManagementException {
        try {
            SignedJWT signedJWT = SignedJWT.parse(refreshToken);
            MACVerifier verifier = new MACVerifier(secretKey.getBytes());
            if (!signedJWT.verify(verifier)) {
                logger.error("Invalid refresh token signature");
                throw new SessionManagementException("Invalid refresh token signature");
            }

            final JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            if (claimsSet.getExpirationTime().getTime() < System.currentTimeMillis()) {
                logger.error("Refresh token expired.");
                throw new SessionManagementException("Refresh token expired.");
            }

            return signedJWT.getJWTClaimsSet();
        } catch (Exception e) {
            final String errMsg = "Error parsing refresh token: " + e.getMessage();
            logger.error(errMsg, e);
            throw new SessionManagementException(errMsg);
        }
    }

    private JWTClaimsSet buildClaims(String userId, String sessionId, long expirationTime) {
        return new JWTClaimsSet.Builder()
                .subject(userId)
                .claim("sid", sessionId)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(expirationTime)))
                .build();
    }

    public long getAccessTokenExpirationTime()
    {
        return ACCESS_TOKEN_EXPIRATION_TIME * 1000;
    }

    public long getRefreshTokenExpirationTime()
    {
        return REFRESH_TOKEN_EXPIRATION_TIME * 1000;
    }
}
