package it.spring.auth_module.utils;

import java.util.regex.Pattern;

public class AppValidator {
    public static final String EMAIL_REGEX = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
    public static final String PASSWORD_REGEX = "^(?=.*[A-Z])(?=(.*[0-9]){2,})(?=.*[!\"£$%\\[&()\\]]).{9,}$";

    private static boolean doNotMatch(String regex, String test) {
        return !Pattern.compile(regex).matcher(test).matches();
    }

    public static boolean invalidEmail(String email) {
        return doNotMatch(EMAIL_REGEX, email);
    }

    /*
     * Password policies:
     * at least 1 uppercase character
     * at least 2 digits
     * at least 1 special character from the following !"£$%[&()]
     * at least 9 characters
     */
    public static boolean invalidPassword(String password) {
        return doNotMatch(PASSWORD_REGEX, password);
    }
}
