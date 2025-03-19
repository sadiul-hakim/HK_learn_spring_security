package xyz.sadiulhakim.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecretController {

    @GetMapping("/secret")
    String secret() {
        return "Nothing";
    }
}
