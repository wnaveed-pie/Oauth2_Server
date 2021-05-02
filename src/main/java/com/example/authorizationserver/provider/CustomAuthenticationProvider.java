package com.example.authorizationserver.provider;


import com.example.authorizationserver.entity.User;
import com.example.authorizationserver.entity.UserBasicInfo;
import com.example.authorizationserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;


@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication auth)
            throws AuthenticationException {

        long start = System.currentTimeMillis();

        try {

            if (StringUtils.isEmpty(auth.getName()) || auth.getCredentials() == null
                    || !(auth.getCredentials() instanceof String)) {
                log.error("Credentials not present");
                return null;
            }

            String username = auth.getName();
            String password = (String) auth.getCredentials();

            User user = userRepository.findByUsername(username);

            if (user == null) {
                log.info(
                        "No user exists in DB. Going to validate credentials from LDAP against username: {}",
                        username);
            }


            if (authenticateFromDb(password, user)) {
                return successAuthenticationResponse(username, password, user);
            }

        } catch (UsernameNotFoundException | DisabledException
                | BadCredentialsException e) {
            // No Need to pollute logs with controlled cases like invalid credentials
            throw e;
        } catch (Exception e) {
            log.error("Exception occurred during authentication:", e);
        } finally {
            long time = System.currentTimeMillis() - start;
            log.info("Total Time of auth(ms): {}", time);
        }

        throw new BadCredentialsException("");

    }

    @Override
    public boolean supports(Class<?> auth) {
        return auth.equals(UsernamePasswordAuthenticationToken.class);
    }


    private boolean authenticateFromDb(String password, User user) {
        if (!passwordEncoder.matches(password, user.getPassword())) {
            log.error("Password not matched against username: {}", user.getUsername());
            return false;
        }
        log.info("Successful DB Authentication against username: {}", user.getUsername());
        return true;
    }

    private UsernamePasswordAuthenticationToken successAuthenticationResponse(
            String username, String password, User user) {
        String roleTitle = user.getRole();
        List<GrantedAuthority> grantedAuthorities = AuthorityUtils
                .commaSeparatedStringToAuthorityList(roleTitle);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                username, password, grantedAuthorities);


        token.setDetails(UserBasicInfo.builder().userId(user.getId().toString())
                .fullName(user.getFirstName() + " " + user.getLastName()).email(user.getEmail()).role(roleTitle).build());



        return token;
    }

}
