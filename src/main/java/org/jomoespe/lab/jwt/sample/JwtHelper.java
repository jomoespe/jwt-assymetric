package org.jomoespe.lab.jwt.sample;

import static io.jsonwebtoken.SignatureAlgorithm.RS256;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.crypto.RsaProvider;

import java.security.Key;
import java.security.KeyPair;

public class JwtHelper {
    public static void main(final String...args) {
        final String token = token( "jomoespe", "Jose Moreno" );
        System.out.printf("token=%s\n\n", token);

        Jws<Claims> claims = claims( token );
        System.out.printf("claims.body.subject = %s\n", claims.getBody().getSubject());
        System.out.printf("claims.body.id = %s\n",      claims.getBody().getId());
    }

    static {
        KeyPair key = RsaProvider.generateKeyPair();
        PRIV = key.getPrivate();
        PUB  = key.getPublic();
        key  = null;
    }
    
    private JwtHelper() { /* provate constructor to avoid instantiation */ }
    
    public static String token(final String id, final String subject) {
        return Jwts.builder()
            .setId( id )
            .setSubject( subject )
            .signWith( RS256, PRIV )
            .compact();
    }

    public static Jws<Claims> claims(final String token) {
        return Jwts.parser()
            .setSigningKey( PUB )
            .parseClaimsJws( token );
    }
    
    private static final Key PRIV;
    private static final Key PUB; 
}
