package com.example.authorizationserver.security;

import com.example.authorizationserver.entity.UserBasicInfo;
import com.example.authorizationserver.utils.SecurityConstants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;
import java.util.Map;

@Slf4j
public class CustomTokenEnhancer implements TokenEnhancer {

	@Value("${auth.refresh-token-validity-seconds}")
	private int refreshTokenValiditySeconds;

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,
			OAuth2Authentication authentication) {

		UserBasicInfo loggedInUser = (UserBasicInfo) authentication
				.getUserAuthentication().getDetails();

		if (loggedInUser == null) {
			// refresh-token case
			loggedInUser = (UserBasicInfo) authentication.getPrincipal();
		}

		if (loggedInUser != null) {
			final Map<String, Object> additionalInfo = new HashMap<>();
			additionalInfo.put(SecurityConstants.USER_ID, loggedInUser.getUserId());
			additionalInfo.put(SecurityConstants.FULL_NAME, loggedInUser.getFullName());
			additionalInfo.put(SecurityConstants.EMAIL, loggedInUser.getEmail());
			additionalInfo.put(SecurityConstants.ROLE, loggedInUser.getRole());
			additionalInfo.put(SecurityConstants.PRIMARY_ROLE,
					loggedInUser.getRole());
			additionalInfo.put(SecurityConstants.REFRESH_TOKEN_EXPIRY,
					refreshTokenValiditySeconds);
			if (loggedInUser.isChangePasswordRequired()) {
				additionalInfo.put(SecurityConstants.CHANGE_PASSWORD_REQUIRED,
						loggedInUser.isChangePasswordRequired());
			}
			((DefaultOAuth2AccessToken) accessToken)
					.setAdditionalInformation(additionalInfo);
		}
		else {
			log.error("Error while decorating Access Token. Invalid request");
		}
		return accessToken;
	}

}
