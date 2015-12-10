package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class ThreadFixAuthenticationProvider extends DaoAuthenticationProvider {

    @Autowired
    private UserService userService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Authentication successAuthentication = super.authenticate(authentication);

        if (successAuthentication != null) {
            if ((successAuthentication.getPrincipal() != null) && (successAuthentication.getPrincipal() instanceof ThreadFixUserDetails)) {
                Integer userId = ((ThreadFixUserDetails) successAuthentication.getPrincipal()).getUserId();
                User user = userService.loadUser(userId);

                if ((user != null) && (user.getSalt() != null) && !user.getSalt().trim().equals("")) {
                    String presentedPassword = String.valueOf(successAuthentication.getCredentials());
                    if ((presentedPassword != null) && !presentedPassword.trim().equals("")) {
                        user.setUnencryptedPassword(presentedPassword);
                        userService.storeUser(user);
                    }
                }
            }
        }

        return successAuthentication;
    }
}
