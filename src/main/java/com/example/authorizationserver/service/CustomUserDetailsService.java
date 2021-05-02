package com.example.authorizationserver.service;

import com.example.authorizationserver.entity.User;
import com.example.authorizationserver.entity.UserBasicInfo;
import com.example.authorizationserver.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * CustomUserDetailsService is used in refresh token flow
 */
@Primary
@Service
@Transactional(rollbackFor = Exception.class, readOnly = true)
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private UserRepository userRepository;

	public UserDetails loadUserByUsername(String username) {
		try {
			if (StringUtils.isEmpty(username)) {
				log.error("Empty username. Invalid Refresh Token");
				throw new UsernameNotFoundException("Invalid refresh token");
			}

			log.info("RefreshToken: Going to check health from DB against username: {}",
					username);
			User user = userRepository.findByUsername(username);
			if (validateUserHealth(user, username)) {
				List<GrantedAuthority> grantedAuthorities = AuthorityUtils
						.commaSeparatedStringToAuthorityList(user.getRole());

				return UserBasicInfo.builder().userId(user.getId().toString())
						.username(user.getUsername()).fullName(user.getFirstName()+" "+user.getLastName())
						.email(user.getEmail()).role(user.getRole())
						.authorities(grantedAuthorities).accountNonExpired(true)
						.accountNonLocked(true).credentialsNonExpired(true).enabled(true).build();
			}
		}
		catch (Exception e) {
			log.error("RefreshToken: Failure! Exception occurred.", e);
		}

		throw new BadCredentialsException(
				"RefreshToken: Request failed against username: " + username);
	}

	private boolean validateUserHealth(User user, String username) {
		if (user == null) {
			log.error(
					"RefreshToken HealthCheck Failed: No user in DB found against username: {}",
					username);
			return false;
		}


		log.info("RefreshToken: HealthCheck Successful. against username: {}", username);
		return true;
	}

}
