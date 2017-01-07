package org.jomoespe.lab.jwt.sample;

import static io.jsonwebtoken.SignatureAlgorithm.RS256;

import static java.lang.System.getenv;
import static java.util.Optional.ofNullable;
import static java.time.Instant.now;
import static java.time.Duration.ofSeconds;
import static java.util.Date.from;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.crypto.RsaProvider;

import java.security.Key;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

public class JwtHelper {
    static {
        KeyPair key = RsaProvider.generateKeyPair();
        PRIV = key.getPrivate();
        PUB  = key.getPublic();
        key  = null;
    }

    private static final String JWT_ID_ENV   = "JWT_ID_ENV";
    private static final String ISSUER_ENV   = "ISSUER_ENV";
    private static final String AUDIENCE_ENV = "AUDIENCE_ENV";

    private static final String JWT_ID_DEFAULT   = "jwt id";
    private static final String ISSUER_DEFAULT   = "jomoespe issuer";
    private static final String AUDIENCE_DEFAULT = "jomoespe jwt test";
    
    private static final String   ROLES_CLAIM_NAME = "roles";
    
    private static final Key      PRIV;
    private static final Key      PUB; 
    
    private static final String   JWT_ID   = ofNullable(getenv(JWT_ID_ENV)).orElse(JWT_ID_DEFAULT);
    private static final String   ISSUER   = ofNullable(getenv(ISSUER_ENV)).orElse(ISSUER_DEFAULT);
    private static final String   AUDIENCE = ofNullable(getenv(AUDIENCE_ENV)).orElse(AUDIENCE_DEFAULT);
    private static final Duration DURATION = ofSeconds( 5 );    // TODO extract duration to environment

    private JwtHelper() { /* private constructor to avoid instantiation */ }
    
    public static final Supplier<Duration> duration = () -> DURATION;

    private static final Function<Instant,Instant> expiration = (date) -> date.plus(duration.get()) ;
    
    private static final Supplier<JwtBuilder> createBaseJwt = () -> 
        Jwts.builder()
            .signWith(RS256, PRIV)
            .setId(JWT_ID)
            .setIssuer(ISSUER)
            .setAudience(AUDIENCE)
            .setIssuedAt(from(now()))
            .setNotBefore(from(now()))
            .setExpiration(from( expiration.apply(now())));
    
    public static final Function<Jws<Claims>, Optional<String>> subject = (claims) -> ofNullable(claims.getBody().getSubject());
    
    public static final Function<Jws<Claims>, Optional<String>> roles = (claims) -> ofNullable(claims.getBody().get(ROLES_CLAIM_NAME, String.class));
    
    public static final BiFunction<String, String, String> token = (subject, role) -> 
        createBaseJwt.get()
            .setSubject(subject)
            .claim(ROLES_CLAIM_NAME, role)
            .compact();

    public static final Function<String, Jws<Claims>> claims = (token) -> 
        Jwts.parser()
            .setSigningKey(PUB )
            .parseClaimsJws(token);
    
    public static final Function<String, String> refresh = (theToken) -> {
        Jws<Claims> tokenClaims = claims.apply(theToken);
        return token.apply( subject.apply(tokenClaims).get(), 
                            roles.apply(tokenClaims).get() );
    };
}
