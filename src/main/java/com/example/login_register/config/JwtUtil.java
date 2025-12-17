package com.example.login_register.config;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;


import java.util.Date;
import java.util.function.Function;


@Component
public class JwtUtil {

    //khoá bí mật : kí token , giải mã token
    @Value("${jwt.secret}")
    private String SECRET;

    //thời gian sống của token
    @Value("${app.jwt.expiration}")
    private long expirationMs;

    //lấy username từ token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //lấy thời gian hết hạn
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //generic để lấy claim bất kỳ
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // giải mã JWT
    // Jwts.parser() : Tạo parser JWT
    // setSigningKey(SECRET) : Dùng secret để xác minh chữ ký
    // parseClaimsJws(token) : Giải mã + kiểm tra token
    // getBody() : Lấy payload (Claims)
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
    }

    // Kiểm tra token hết hạn
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Lấy Role từ token
    public String extractRole(String token) {
        return extractAllClaims(token).get("role", String.class);
    }


    // Tạo JWT
    public String generateToken(String username , String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(SignatureAlgorithm.HS256, SECRET)
                .compact();
    }

    //Kiểm tra token : username trong token = username trong DB
                    // token chưa hết hạn
    public Boolean validateToken(String token, String username) {
        final String extractedUsername = extractUsername(token);
        return (extractedUsername.equals(username) && !isTokenExpired(token));
    }
}

