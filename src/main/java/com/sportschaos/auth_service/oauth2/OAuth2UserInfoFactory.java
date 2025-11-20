package com.sportschaos.auth_service.oauth2;


import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if (registrationId.equalsIgnoreCase("google")) {
            return new GoogleOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase("github")) {
           return new GithubOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase("facebook")) {
            return new FacebookOAuth2UserInfo(attributes);
        }else {
            throw new IllegalArgumentException("Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }
}
