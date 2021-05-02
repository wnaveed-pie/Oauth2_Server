package com.example.authorizationserver.utils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

public class SecurityUtils {

	public static final String SIGNING_KEY = "as466gf";

	/**
	 * returns common CORS configurations to be used for all services
	 * @return {@link CorsConfigurationSource )
	 */
	public static CorsConfigurationSource getCommonCorsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("*"));
		configuration.setAllowedHeaders(Arrays.asList("*"));
		configuration.setAllowCredentials(Boolean.TRUE);
		configuration.setAllowedMethods(
				Arrays.asList("GET", "POST", "OPTIONS", "PATCH", "PUT", "DELETE"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
	public static void validateWithLoggedUser(String userName) {

		String loggedInUserName = getLoggedInUserName();
		if (!userName.equals(loggedInUserName)) {
			throw new UsernameNotFoundException("No logged in user found with userName: " + userName);
		}
	}

	public static String getLoggedInUserName() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		return (auth!=null)?(String) auth.getPrincipal():null;
	}

}
