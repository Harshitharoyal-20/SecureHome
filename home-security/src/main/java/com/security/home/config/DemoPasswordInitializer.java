
package com.security.home.config;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DemoPasswordInitializer implements ApplicationRunner {

    private final JdbcTemplate jdbc;
    private final PasswordEncoder encoder;

    public DemoPasswordInitializer(
            JdbcTemplate jdbc,
            PasswordEncoder encoder) {
        this.jdbc = jdbc;
        this.encoder = encoder;
    }

    @Override
    public void run(ApplicationArguments args) {
        updatePassword("sivakumar6413@gmail.com", "sivakumar@123");
        updatePassword("pranawii0713@gmail.com", "pranawii@0713");
        updatePassword("harshitha0064@gmail.com", "harshitha@0064");
        updatePassword("mahesh0562@gmail.com", "mahesh@05623");
    }

    private void updatePassword(String email, String password) {
        String hash = encoder.encode(password);

        int updated = jdbc.update(
            "UPDATE users SET password_hash = ? WHERE email = ?",
            hash,
            email
        );

        if (updated != 1) {
            throw new IllegalStateException(
                "Expected one account for email: " + email
            );
        }
    }
}
