package xyz.sadiulhakim.SecureSpringApp.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NameController {

    @GetMapping("/who_is_he")
    String whoIsHe(@RequestParam String shortName) {
        if (shortName.equalsIgnoreCase("hakim"))
            return "Sadiul Hakim";

        return "None";
    }
}
