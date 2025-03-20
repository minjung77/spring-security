package project.houseway.springsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
    @GetMapping("/")
    public String index() {
        return "Hello World";
    }
    // user, admin 접속 가능
    @GetMapping("/user")
    public String user() {
        return "Hello user";
    }
    // admin 접속 가능
    @GetMapping("/admin")
    public String admin() {
        return "Hello admin";
    }
}
