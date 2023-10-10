package com.security.auth;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserRestApi {
    @GetMapping("private/userdata")
    public ResponseEntity<String> getPrivateData(@RequestAttribute(name="username") String username){

        //We get here only if the MyTokenFilter gets through and the user is validated.
        return new ResponseEntity<String>("Personal data for " + username, HttpStatus.OK);
    }

    // @GetMapping("private/usedata")
    // public ResponseEntity<String> getPrivateData(@RequestHeader("Authorization") String bearer){

    //     if(bearer.startsWith("Bearer")){
    //         String token = bearer.split(" ")[1];
    //         String username = secService.validateJwt(token);
    //         if(username!=null){
    //             return new ResponseEntity<>("Private data for "+username, HttpStatus.OK);
    //         }
    //     }

    //     return new ResponseEntity<>(HttpStatus.FORBIDDEN);
    // }
}
