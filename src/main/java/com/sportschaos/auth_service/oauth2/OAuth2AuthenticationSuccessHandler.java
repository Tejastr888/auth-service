package com.sportschaos.auth_service.oauth2;

import com.sportschaos.auth_service.entity.User;
import com.sportschaos.auth_service.util.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;

    @Value("${app.oauth2.authorized-redirect-uri:http://localhost:3000/oauth2/redirect}")
    private String redirectUri;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {

        CustomOAuth2User oauth2User = (CustomOAuth2User) authentication.getPrincipal();
        User user = oauth2User.getUser();

        // Generate JWT token
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("role", user.getRole().name());
        extraClaims.put("userId", user.getId());
        extraClaims.put("provider", user.getProvider());

        String token = jwtUtil.generateToken(user, extraClaims);

        log.info("OAuth2 login successful for user: {} via provider: {}", user.getEmail(), user.getProvider());

        // Redirect to frontend with token
        return UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("token", token)
                .queryParam("userId", user.getId())
                .queryParam("email", user.getEmail())
                .queryParam("name", user.getName())
                .queryParam("role", user.getRole().name())
                .build()
                .toUriString();
    }
}