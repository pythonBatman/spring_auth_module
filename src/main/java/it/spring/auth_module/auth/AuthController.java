package it.spring.auth_module.auth;

import it.spring.auth_module.auth.roles.AuthRoles;
import it.spring.auth_module.models.AppToken;
import it.spring.auth_module.models.AppUser;
import it.spring.auth_module.models.requests.*;
import it.spring.auth_module.utils.AppEncrypt;
import it.spring.auth_module.utils.AppSession;
import it.spring.auth_module.utils.AppValidator;
import it.spring.auth_module.utils.Responses;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/login")
    public Map<String, Object> login(HttpSession session, @RequestBody LoginRequest request,
                                     @RequestHeader("User-Agent") String userAgent) {
        if (request.isNotValidRequest()) {
            Responses.badRequest();
        } else if (AppSession.isUserLoggedIn(session)) {
            Responses.userAlreadyLoggedIn();
        }
        AppUser appUser = authService.getAppUserByUsername(request.username().toLowerCase());
        if (appUser.isIncorrectPassword(request.password())) {
            Responses.badCredentials();
        } else if (appUser.isNotEnabled()) {
            Responses.userNotEnabled();
        } else if (appUser.isLocked()) {
            Responses.userLocked();
        } else if (appUser.needToChangePassword()) {
            Responses.needToChangePassword();
        }
        AppSession.setAuthUser(session, appUser, request.rememberMe());
        AppSession.setUserAgent(session, userAgent);
        String loginToken = request.generateLoginToken() ? authService.createToken(appUser, AppToken.Type.login) : null;
        return appUser.getPublicData(loginToken);
    }

    @PostMapping("/two-factor-login")
    public Map<String, String> twoFactorLogin(HttpSession session, @RequestBody LoginRequest request,
                                              @RequestHeader("User-Agent") String userAgent) {
        if (request.isNotValidRequest()) {
            Responses.badRequest();
        } else if (AppSession.isUserLoggedInEvenTemporary(session)) {
            Responses.userAlreadyLoggedIn();
        }
        AppUser appUser = authService.getAppUserByUsername(request.username().toLowerCase());
        if (appUser.isIncorrectPassword(request.password())) {
            Responses.badCredentials();
        } else if (appUser.isNotEnabled()) {
            Responses.userNotEnabled();
        } else if (appUser.isLocked()) {
            Responses.userLocked();
        } else if (appUser.needToChangePassword()) {
            Responses.needToChangePassword();
        }
        String otpCode = AppEncrypt.generateOtpCode();
        AppSession.setTemporaryAuthUser(session, appUser);
        AppSession.setUserAgent(session, userAgent);
        AppSession.setOtpCode(session, otpCode);
        AppSession.setRememberMe(session, request.rememberMe());
        AppSession.setGenerateLoginToken(session, request.generateLoginToken());
        // TODO: Send email or sms with otp code
        System.out.println("OTP code created: " + otpCode);
        return Responses.success();
    }

    @PostMapping("/otp-code")
    public Map<String, Object> otpCode(HttpSession session, @RequestBody OtpRequest request,
                                       @RequestHeader("User-Agent") String userAgent) {
        if (request.isNotValidRequest()) {
            Responses.badRequest();
        } else if (AppSession.isNotTemporaryUser(session)) {
            Responses.unauthorized();
        } else if (!AppSession.getOtpCode(session).equals(request.otpCode())) {
            Responses.invalidOptCode();
        }
        AppUser appUser = AppSession.getTemporaryAuthUser(session);
        AppSession.setAuthUser(session, appUser, AppSession.getRememberMe(session));
        AppSession.setUserAgent(session, userAgent);
        String loginToken = AppSession.getGenerateLoginToken(session) ? authService.createToken(appUser, AppToken.Type.login) : null;
        AppSession.removeTemporaryInformation(session);
        return appUser.getPublicData(loginToken);
    }

    @PostMapping("/login-with-token")
    public Map<String, Object> loginWithToken(HttpSession session, @RequestBody TokenRequest request,
                                              @RequestHeader("User-Agent") String userAgent) {
        if (request.isNotValidRequest()) {
            Responses.badRequest();
        } else if (AppSession.isUserLoggedIn(session)) {
            Responses.userAlreadyLoggedIn();
        }
        AppToken appToken = authService.getAppTokenByToken(request.token());
        if (appToken.isExpired()) {
            Responses.expiredToken();
        } else if (appToken.getAppUser().isNotEnabled()) {
            Responses.userNotEnabled();
        } else if (appToken.getAppUser().isLocked()) {
            Responses.userLocked();
        }
        AppSession.setAuthUser(session, appToken.getAppUser(), request.rememberMe());
        AppSession.setUserAgent(session, userAgent);
        authService.updateToken(appToken);
        return appToken.getAppUser().getPublicData();
    }

    @GetMapping("/logout")
    public Map<String, String> logout(HttpSession session) {
        AppSession.logout(session);
        return Responses.success();
    }

    @PostMapping("/registration-user")
    public Map<String, String> registrationUser(@RequestBody RegistrationRequest request) {
        if (request.isNotValidRequest()) {
            Responses.badRequest();
        } else if (AppValidator.invalidEmail(request.username().toLowerCase())) {
            Responses.invalidEmail();
        } else if (AppValidator.invalidPassword(request.password())) {
            Responses.invalidPassword();
        }
        AppUser appUser = authService.createAppUser(request, AuthRoles.Roles.user);
        String token = authService.createToken(appUser, AppToken.Type.confirmation);
        // TODO: Send email or sms with confirmation token
        System.out.println("Confirmation token created: " + token);
        return Responses.success();
    }

    @GetMapping("/confirmation/{token}")
    public Map<String, String> confirmation(@PathVariable("token") String token) {
        AppToken appToken = authService.getAppTokenByToken(token);
        if (appToken.getAppUser().isEnabled()) {
            Responses.userAlreadyConfirmed();
        } else if (appToken.isExpired()) {
            Responses.expiredToken();
        }
        authService.enableAppUser(appToken.getAppUser());
        authService.updateToken(appToken);
        return Responses.success();
    }

    @DeleteMapping("/login-token")
    public Map<String, String> deleteLoginToken(@RequestBody TokenRequest request) {
        if (request.isNotValidRequest()) {
            Responses.badRequest();
        }
        AppToken appToken = authService.getAppTokenByToken(request.token());
        if (appToken.isNotLoginToken()) {
            Responses.tokenNotFound();
        }
        authService.deleteToken(appToken);
        return Responses.success();
    }

    @PostMapping("/verify-login-token")
    public Map<String, Boolean> verifyLoginToken(@RequestBody TokenRequest request) {
        if (request.isNotValidRequest()) {
            Responses.badRequest();
        }
        AppToken appToken = authService.getAppTokenByToken(request.token());
        if (appToken.isNotLoginToken()) {
            Responses.tokenNotFound();
        }
        Boolean validation = !appToken.isExpired();
        return Map.of("message", validation);
    }

    @PostMapping("/change-password")
    public Map<String, String> changePassword(@RequestBody ChangePasswordRequest request) {
        if (request.isNotValidRequest()) {
            Responses.badRequest();
        } else if (AppValidator.invalidPassword(request.newPassword())) {
            Responses.invalidPassword();
        }
        AppUser appUser = authService.getAppUserByUsername(request.username().toLowerCase());
        if (appUser.isIncorrectPassword(request.currentPassword())) {
            Responses.badCredentials();
        } else if (appUser.verifyPassword(request.newPassword())) {
            Responses.passwordMustBeDifferentFromTheCurrentOne();
        }
        authService.updateAppUserPassword(appUser, request.newPassword());
        return Responses.success();
    }

    @PostMapping("/reset-password-request")
    public Map<String, String> resetPasswordRequest(HttpSession session, @RequestBody ResetPasswordRequest request) {
        if (request.isNotValidRequest()) {
            Responses.badRequest();
        } else if (AppSession.isUserLoggedIn(session)) {
            Responses.userAlreadyLoggedIn();
        }
        AppUser appUser = authService.getAppUserByUsername(request.username().toLowerCase());
        if (appUser.isLocked()) {
            Responses.userLocked();
        }
        String token = authService.createToken(appUser, AppToken.Type.resetPassword);
        // TODO: Send email or sms with reset password token
        System.out.println("Reset password token created: " + token);
        return Responses.success();
    }

    @PostMapping("/reset-password")
    public Map<String, String> resetPassword(@RequestBody ResetPasswordTokenRequest request) {
        if (request.isNotValidRequest()) {
            Responses.badRequest();
        }
        AppToken appToken = authService.getAppTokenByToken(request.token());
        if (appToken.getAppUser().isLocked()) {
            Responses.userLocked();
        } else if (appToken.isExpired()) {
            Responses.expiredToken();
        } else if (AppValidator.invalidPassword(request.newPassword())) {
            Responses.invalidPassword();
        } else if (appToken.getAppUser().verifyPassword(request.newPassword())) {
            Responses.passwordMustBeDifferentFromTheCurrentOne();
        }
        authService.updateAppUserPassword(appToken.getAppUser(), request.newPassword());
        authService.updateToken(appToken);
        return Responses.success();
    }

    @GetMapping("/user-info")
    @AuthRoles
    public Map<String, Object> userInfo(HttpSession session) {
        return AppSession.getAuthUser(session).getPublicData();
    }
}
