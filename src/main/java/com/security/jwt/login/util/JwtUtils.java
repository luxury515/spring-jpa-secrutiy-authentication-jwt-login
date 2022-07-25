package com.security.jwt.login.util;


import com.security.jwt.login.service.CustomUserDetails;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import java.util.Date;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

@Slf4j
@Component // 해당 어노테이션을 선언하지 않으면 값 할당이 안되어서 static 변수 값이 null .
public class JwtUtils {

    private static String jwtSecret;

    @Value("${broker.app.jwtSecret}")
    public void setJwtSecret(String jwtSecret) {
        JwtUtils.jwtSecret = jwtSecret;
    }

    private static int jwtExpirationMs;

    @Value("${broker.app.jwtExpirationMs}")
    public void setJwtExpirationMs(int jwtExpirationMs) {
        JwtUtils.jwtExpirationMs = jwtExpirationMs;
    }

    private static int jwtExpirationRefresh;

    @Value("${broker.app.jwtExpirationRefresh}")
    public void setJwtExpirationRefresh(int jwtExpirationRefresh) {
        JwtUtils.jwtExpirationRefresh = jwtExpirationRefresh;
    }

    private static String jwtCookie;

    @Value("${broker.app.jwtCookieName}")
    public void setJwtCookie(String jwtCookie) {
        JwtUtils.jwtCookie = jwtCookie;
    }

    public static String getJwtFromCookies(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, jwtCookie);
        if (cookie != null) {
            return cookie.getValue();
        } else {
            return null;
        }
    }

    public static ResponseCookie generateJwtCookie(CustomUserDetails userPrincipal) {
        String jwt = generateAccessTokenFromUsername(userPrincipal.getUsername());
        return ResponseCookie.from(jwtCookie, jwt)
            .path("/api")
            .maxAge(24 * 60 * 60)
            .httpOnly(true)
            .build();
    }

    public static ResponseCookie getCleanJwtCookie() {
        return ResponseCookie.from(JwtUtils.jwtCookie, null).path("/api").build();
    }

    public static String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
            .setSigningKey(JwtUtils.jwtSecret)
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }

    public static boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(JwtUtils.jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }

    public static String generateAccessTokenFromUsername(String username) {
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(new Date())
            .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
            .signWith(SignatureAlgorithm.HS512, jwtSecret)
            .compact();
    }

    public static String generateRefreshTokenFromUsername(String username) {
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(new Date())
            .setExpiration(new Date((new Date()).getTime() + jwtExpirationRefresh))
            .signWith(SignatureAlgorithm.HS512, jwtSecret)
            .compact();
    }
}
