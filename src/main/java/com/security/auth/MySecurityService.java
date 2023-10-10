package com.security.auth;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

@Service
public class MySecurityService {
    
    @Value("${jwt.secret}")
    private String jwtKey;

    PersonRepository repo;

    public MySecurityService(PersonRepository repository){
        this.repo = repository;
    }

    /**
     * Register new user or update existing one
     */
    public User register(String uname, String pw){
        
        User user = new User(uname, BCrypt.hashpw(pw, BCrypt.gensalt(10)));
        repo.save(user);
        return user;
    }

    /**
     * Login user. Return JWT token or null if not found or wrong password.
     */
    public String login(String uname, String pw){
     
        User user = repo.findById(uname).orElse(null);

        if(user == null || !BCrypt.checkpw(pw, user.getPassword())){
            return null;
        }

        Algorithm alg = Algorithm.HMAC256(jwtKey);
        return JWT.create().withSubject(user.getUsername()).sign(alg);
    }

    /**
     * Verify jwt token and return username if token is valid
     */
    public String validateJwt(String jwtToken){
        Algorithm alg = Algorithm.HMAC256(jwtKey);
        JWTVerifier verifier = JWT.require(alg).build();

        try {
            DecodedJWT jwt = verifier.verify(jwtToken);
            return jwt.getSubject();
        } catch (JWTVerificationException e) {
            System.out.println(e.getMessage());
        }

        return null;
    }
}
