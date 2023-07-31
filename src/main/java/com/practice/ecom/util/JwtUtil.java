package com.practice.ecom.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    // TODO: Make this more secure
    private static final String SECRET_KEY = "ecommerce_be";
    private static final int TOKEN_VALIDITY_DURATION = 3600 * 5; //5 hours

    public String getUserNameFromToken(String jwtToken){
        return getClaimFromToken(jwtToken, Claims::getSubject);
    }

    private <T> T getClaimFromToken(String jwtToken, Function<Claims, T> claimResolver){
        Claims claims = getAllClaimsFromToken(jwtToken);
        return claimResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String jwtToken){
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(jwtToken).getBody();
    }

    public boolean validateToken(String jwtToken, UserDetails userDetails){
        String userName = getUserNameFromToken(jwtToken);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(jwtToken));
    }

    private boolean isTokenExpired(String jwtToken){
        Date expDate = getExpDateFromToken(jwtToken);
        return expDate.before(new Date());
    }

    private Date getExpDateFromToken(String jwtToken){
        return getClaimFromToken(jwtToken, Claims::getExpiration);
    }

    public String generateToken(UserDetails userDetails){
        Map<String, Object> claims = new HashMap<>();

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_VALIDITY_DURATION * 1000))
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact()
                ;
    }
}
