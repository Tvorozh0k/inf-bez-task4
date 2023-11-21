package com.edu.task4;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.DefaultJwtSignatureValidator;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/")
public class UserController {
    @Autowired
    private UserRepository userRepository;

    @PostMapping("/registrate")
    public ResponseEntity<?> createAccount(@RequestBody Map<String, String> accInfo) throws NoSuchAlgorithmException {
        if (!accInfo.keySet().equals(Set.of("login", "password"))) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        if (accInfo.get("login").isEmpty() || accInfo.get("login").length() > 50) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        if (accInfo.get("password").isEmpty() || accInfo.get("password").length() > 50) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        byte[] salt = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);

        byte[] password = accInfo.get("password").getBytes(StandardCharsets.UTF_8);

        ByteBuffer result = ByteBuffer.allocate(salt.length + password.length);
        result.put(salt);
        result.put(password);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] saltPassword = digest.digest(result.array());

        try {
            User user = new User(accInfo.get("login"), salt, saltPassword);
            userRepository.save(user);
            return new ResponseEntity<>(HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/auth")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> accInfo, HttpServletResponse response) throws NoSuchAlgorithmException {
        if (!accInfo.keySet().equals(Set.of("login", "password"))) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        if (accInfo.get("login").isEmpty() || accInfo.get("login").length() > 50) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        if (accInfo.get("password").isEmpty() || accInfo.get("password").length() > 50) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        User user = userRepository.findAll().stream()
                .filter(usr -> usr.getLogin().equals(accInfo.get("login")))
                .findAny()
                .orElse(null);

        if (user == null) {
            return new ResponseEntity<>(Map.of("message", "Пользователя с заданным логином не существует"),
                    HttpStatus.BAD_REQUEST);
        }

        byte[] password = accInfo.get("password").getBytes(StandardCharsets.UTF_8);

        ByteBuffer result = ByteBuffer.allocate(user.getSalt().length + password.length);
        result.put(user.getSalt());
        result.put(password);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] saltPassword = digest.digest(result.array());

        if (!Arrays.equals(user.getSaltPassword(), saltPassword)) {
            return new ResponseEntity<>(Map.of("message", "Неправильный пароль"),
                    HttpStatus.BAD_REQUEST);
        }

        final Cookie accessTokenCookie = new Cookie("Access-Token", TokenGenerator.generateAccessToken(user.getId(), user.getLogin()));
        accessTokenCookie.setHttpOnly(true);
        response.addCookie(accessTokenCookie);

        final Cookie refreshTokenCookie = new Cookie("Refresh-Token", TokenGenerator.generateRefreshToken(user.getLogin()));
        refreshTokenCookie.setHttpOnly(true);
        response.addCookie(refreshTokenCookie);

        return new ResponseEntity<>(Map.of("message", String.format("Здравствуйте, %s", user.getLogin())), HttpStatus.OK);
    }

    @PostMapping("/refresh")
    public ResponseEntity<String> refreshTokens(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("Refresh-Token".equals(cookie.getName())) {
                    String refreshToken = cookie.getValue();

                    SignatureAlgorithm sa = SignatureAlgorithm.HS256;
                    SecretKeySpec secretKeySpec = new SecretKeySpec("tHWethDHqoSdbG8kAnMBOgOyvcSBAWFbt7qTL550yD4PSd8HdoCsXhwacDrWyzz".getBytes(), sa.getJcaName());

                    String[] chunks = refreshToken.split("\\.");
                    String tokenWithoutSignature = chunks[0] + "." + chunks[1];
                    String signature = chunks[2];

                    DefaultJwtSignatureValidator validator = new DefaultJwtSignatureValidator(sa, secretKeySpec);

                    if (validator.isValid(tokenWithoutSignature, signature)) {
                        Base64.Decoder decoder = Base64.getUrlDecoder();

                        String[] payload = new String(decoder.decode(chunks[1])).split("\"");

                        User user = userRepository.findAll().stream()
                                .filter(usr -> usr.getLogin().equals(payload[3]))
                                .findAny()
                                .orElse(null);

                        final Cookie accessTokenCookie = new Cookie("Access-Token", TokenGenerator.generateAccessToken(user.getId(), user.getLogin()));
                        accessTokenCookie.setHttpOnly(true);
                        response.addCookie(accessTokenCookie);

                        final Cookie refreshTokenCookie = new Cookie("Refresh-Token", TokenGenerator.generateRefreshToken(user.getLogin()));
                        refreshTokenCookie.setHttpOnly(true);
                        response.addCookie(refreshTokenCookie);

                        return new ResponseEntity<>("Token refreshed successfully", HttpStatus.OK);
                    } else {
                        return new ResponseEntity<>("Invalid refresh token", HttpStatus.FORBIDDEN);
                    }
                }
            }
        }

        return new ResponseEntity<>("Refresh token not provided", HttpStatus.FORBIDDEN);
    }
}
