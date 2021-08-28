package com.okoroefe.demo.auth;

import com.google.common.collect.Lists;
import com.okoroefe.demo.security.ApplicationUserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.okoroefe.demo.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDao implements ApplicationUserDao{

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDao(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers().stream().filter(user -> user.getUsername().equals(username)).findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        return Lists.newArrayList(
                new ApplicationUser(
                        STUDENT.getGrantedAuthorities(),
                        "efe",
                        passwordEncoder.encode("password"),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        ADMIN.getGrantedAuthorities(),
                        "admin",
                        passwordEncoder.encode("password"),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        ADMINTRAINEE.getGrantedAuthorities(),
                        "admin2",
                        passwordEncoder.encode("password"),
                        true,
                        true,
                        true,
                        true
                )
        );
    }
}
