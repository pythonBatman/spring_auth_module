package it.spring.auth_module.auth;

import it.spring.auth_module.auth.roles.AuthRoles;
import it.spring.auth_module.models.AppToken;
import it.spring.auth_module.models.AppUser;
import it.spring.auth_module.models.repositories.AppTokenRepository;
import it.spring.auth_module.models.repositories.AppUserRepository;
import it.spring.auth_module.models.requests.RegistrationRequest;
import it.spring.auth_module.utils.AppEncrypt;
import it.spring.auth_module.utils.Responses;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@AllArgsConstructor
@Service
public class AuthService {
    private final AppUserRepository appUserRepository;
    private final AppTokenRepository appTokenRepository;

    private void checkAppUserAlreadyExists(String username) {
        if (appUserRepository.findAppUserByUsername(username).isPresent()) {
            Responses.userAlreadyExists();
        }
    }

    public AppUser getAppUserByUsername(String username) {
        Optional<AppUser> optionalAppUser = appUserRepository.findAppUserByUsername(username);
        if (optionalAppUser.isEmpty()) {
            Responses.userNotFound();
        }
        return optionalAppUser.get();
    }

    public AppToken getAppTokenByToken(String token) {
        Optional<AppToken> optionalAppToken = appTokenRepository.findAppTokenByToken(token);
        if (optionalAppToken.isEmpty()) {
            Responses.tokenNotFound();
        }
        return optionalAppToken.get();
    }

    public AppUser createAppUser(RegistrationRequest request, AuthRoles.Roles appUserRole) {
        checkAppUserAlreadyExists(request.username().toLowerCase());
        AppUser appUser = new AppUser(request);
        appUser.setRole(appUserRole);
        try {
            appUserRepository.save(appUser);
        } catch (Exception e) {
            Responses.databaseError();
        }
        return appUser;
    }

    public String createToken(AppUser appUser, AppToken.Type type) {
        AppToken appToken = new AppToken(appUser, type);
        try {
            appTokenRepository.save(appToken);
        } catch (Exception e) {
            Responses.databaseError();
        }
        return appToken.getToken();
    }

    @Transactional
    public void updateAppUserPassword(AppUser appUser, String newPassword) {
        try {
            String salt = AppEncrypt.generateSalt();
            String secretPassword = AppEncrypt.generateSecurePassword(newPassword, salt);
            appUser.setPassword(secretPassword);
            appUser.setPasswordSalt(salt);
            appUser.setChangedPasswordAt(LocalDateTime.now());
        } catch (Exception e) {
            Responses.databaseError();
        }
    }

    @Transactional
    public void enableAppUser(AppUser appUser) {
        try {
            if (appUser.isNotEnabled()) {
                appUser.setEnabledAt(LocalDateTime.now());
            }
        } catch (Exception e) {
            Responses.databaseError();
        }
    }

    @Transactional
    public void updateToken(AppToken appToken) {
        try {
            appToken.setRequestTimes(appToken.getRequestTimes() + 1);
            appToken.setUpdatedAt(LocalDateTime.now());
        } catch (Exception e) {
            Responses.databaseError();
        }
    }

    public void deleteToken(AppToken appToken) {
        try {
            appTokenRepository.delete(appToken);
        } catch (Exception e) {
            Responses.databaseError();
        }
    }
}

