package com.security.auth.rest;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.security.auth.data.User;
import com.security.auth.service.MySecurityService;


@RestController
public class SecurityRestApi {
    @Autowired
    MySecurityService secService;

    /**
     * Register user with request parameters
     */
    @PostMapping("register")
    public ResponseEntity<String> register(
        @RequestParam String uname, 
        @RequestParam String pw)
    {
        User u = secService.register(uname, pw);
        return new ResponseEntity<>(u.getUsername(), HttpStatus.OK);
    }

    /**
     * Login user with request parameters.
     * Returns token if user is authorized.
     */
    @PostMapping("login")
    public ResponseEntity<Map<String,String>> login(
        @RequestParam String uname, 
        @RequestParam String pw)
    {
        String token = secService.login(uname, pw);

         return createResponse(token);
    }
 
    /**
     * Another version for login with basic authentication header. 
     */
    @PostMapping("loginbasic")
    public ResponseEntity<Map<String,String>> loginBasic(@RequestHeader("Authorization") String basicAuth)
    {
        String token = null;
        //"Basic uname:pw"
        if(basicAuth.startsWith("Basic")){
            String credentials = basicAuth.split(" ")[1];
            String[] user = new String( Base64.getDecoder().decode(credentials)).split(":");
            token = secService.login(user[0], user[1]);
        }
        return createResponse(token);
    }

    private ResponseEntity<Map<String,String>> createResponse(String token){
        if(token == null){
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        
        Map<String,String> response =  new HashMap<>();
        response.put("token", token);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
