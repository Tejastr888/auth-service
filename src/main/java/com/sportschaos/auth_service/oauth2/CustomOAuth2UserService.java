package com.sportschaos.auth_service.oauth2;

import com.sportschaos.auth_service.entity.User;
import com.sportschaos.auth_service.entity.Role;
import com.sportschaos.auth_service.entity.UserStatus;
import com.sportschaos.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);

        try {
            return processOAuth2User(userRequest, oauth2User);
        } catch (Exception ex) {
            log.error("Error processing OAuth2 user", ex);
            throw new OAuth2AuthenticationException("Error processing OAuth2 user: " + ex.getMessage());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oauth2User) {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2UserInfo oauth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, oauth2User.getAttributes());

        if (oauth2UserInfo.getEmail() == null || oauth2UserInfo.getEmail().isEmpty()) {
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(oauth2UserInfo.getEmail());
        User user;

        if (userOptional.isPresent()) {
            user = userOptional.get();
            user = updateExistingUser(user, oauth2UserInfo, registrationId);
        } else {
            user = registerNewUser(oauth2UserInfo, registrationId);
        }

        return new CustomOAuth2User(user, oauth2User.getAttributes());
    }

    private User registerNewUser(OAuth2UserInfo oauth2UserInfo, String provider) {
        User user = new User();
        user.setName(oauth2UserInfo.getName());
        user.setEmail(oauth2UserInfo.getEmail());
        user.setProvider(provider);
        user.setProviderId(oauth2UserInfo.getId());
        user.setRole(Role.USER);
        user.setStatus(UserStatus.ACTIVE);
        // No password needed for OAuth2 users
        user.setPassword("");

        log.info("Registering new OAuth2 user: {} from provider: {}", user.getEmail(), provider);
        return userRepository.save(user);
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo oauth2UserInfo, String provider) {
        existingUser.setName(oauth2UserInfo.getName());
        existingUser.setProvider(provider);
        existingUser.setProviderId(oauth2UserInfo.getId());

        log.info("Updating existing OAuth2 user: {} from provider: {}", existingUser.getEmail(), provider);
        return userRepository.save(existingUser);
    }
}

