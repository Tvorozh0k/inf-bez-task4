package com.edu.task4;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.util.Date;

public class TokenGenerator {
    private static final String ACCESS_TOKEN_SECRET = "4OCU6f2yZMXZYqV1Em3scW4XUisHeO7qxBLhpwmdYNEVcCtuxmQjV4X0OfpmE8V";
    private static final String REFRESH_TOKEN_SECRET = "tHWethDHqoSdbG8kAnMBOgOyvcSBAWFbt7qTL550yD4PSd8HdoCsXhwacDrWyzz";

    public static String generateAccessToken(int id, String login) {
        return Jwts.builder()
                .claim("UserInfo", new UserInfo(id, login))
                .signWith(Keys.hmacShaKeyFor(ACCESS_TOKEN_SECRET.getBytes()), SignatureAlgorithm.HS256)
                .setExpiration(new Date(System.currentTimeMillis() + 600000)) // 10 minutes
                .compact();
    }

    public static String generateRefreshToken(String login) {
        return Jwts.builder()
                .claim("login", login)
                .signWith(Keys.hmacShaKeyFor(REFRESH_TOKEN_SECRET.getBytes()), SignatureAlgorithm.HS256)
                .setExpiration(new Date(System.currentTimeMillis() + 43200000)) // 12 hours
                .compact();
    }
}
