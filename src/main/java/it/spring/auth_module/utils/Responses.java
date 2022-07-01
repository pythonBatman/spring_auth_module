package it.spring.auth_module.utils;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

public class Responses {

    public static Map<String, String> success() {
        return Map.of("message", "success");
    }

    public static void internalServerError() {
        throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    public static void badRequest() {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid request, check if every required fields were passed");
    }

    public static void databaseError() {
        throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Database error, check if every required fields were passed");
    }

    public static void unauthorized() {
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    }

    public static void userAlreadyExists() {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "User already exists");
    }

    public static void userNotFound() {
        throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found");
    }

    public static void tokenNotFound() {
        throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Token not found");
    }

    public static void userNotEnabled() {
        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "User not enabled");
    }

    public static void userLocked() {
        throw new ResponseStatusException(HttpStatus.LOCKED, "User account is locked");
    }

    public static void badCredentials() {
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bad credentials");
    }

    public static void needToChangePassword() {
        throw new ResponseStatusException(HttpStatus.UPGRADE_REQUIRED, "User needs to change password");
    }

    public static void userAlreadyLoggedIn() {
        throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, "User already logged in");
    }

    public static void invalidEmail() {
        throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, "Invalid email");
    }

    public static void invalidPassword() {
        throw new ResponseStatusException(HttpStatus.PRECONDITION_FAILED, "Password does not match criteria");
    }

    public static void forbiddenResource() {
        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "User does not have privileges for this resource");
    }

    public static void expiredToken() {
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Expired token");
    }

    public static void userAlreadyConfirmed() {
        throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, "User already confirmed");
    }

    public static void passwordMustBeDifferentFromTheCurrentOne() {
        throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, "The password must be different from the current one");
    }

    public static void invalidOptCode() {
        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid otp code");
    }
}
