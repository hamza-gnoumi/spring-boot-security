package com.example.springbootsecurity.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.springbootsecurity.security.ApplicationUserRole.*;
@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{

    private final PasswordEncoder passwordEncoder;
    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers().stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser>getApplicationUsers(){
        List<ApplicationUser>applicationUsers= Lists.newArrayList(
                new ApplicationUser(ADMIN.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "hamza",
                        true,
                        true,
                        true,
                        true),
                new ApplicationUser(STUDENT.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "ahmed",
                        true,
                        true,
                        true,
                        true),
                new ApplicationUser(ADMINTRAINEE.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "amir",
                        true,
                        true,
                        true,
                        true)

        );
        return applicationUsers;
    }
}
