package it.spring.auth_module.utils;

import it.spring.auth_module.models.AppUser;

import javax.servlet.http.HttpSession;

public class AppSession {
    private static final String AUTH_USER = "AUTH_USER";
    private static final String TEMPORARY_AUTH_USER = "TEMPORARY_AUTH_USER";
    private static final String USER_AGENT = "USER_AGENT";
    private static final String OTP_CODE = "OTP_CODE";
    private static final String REMEMBER_ME = "REMEMBER_ME";
    private static final String GENERATE_LOGIN_TOKEN = "GENERATE_LOGIN_TOKEN";
    private static final int INACTIVE_TIME_30_DAYS = 2592000;
    private static final int INACTIVE_TIME_30_MINUTES = 1800;

    public static boolean isUserLoggedIn(HttpSession session) {
        return getAuthUser(session) != null;
    }

    public static boolean isUserLoggedInEvenTemporary(HttpSession session) {
        return getAuthUser(session) != null || getTemporaryAuthUser(session) != null;
    }

    public static boolean isNotTemporaryUser(HttpSession session) {
        return getAuthUser(session) != null || getTemporaryAuthUser(session) == null;
    }

    public static void logout(HttpSession session) {
        session.invalidate();
    }

    public static void setAuthUser(HttpSession session, AppUser user, boolean rememberMe) {
        session.setMaxInactiveInterval(rememberMe ? INACTIVE_TIME_30_DAYS : INACTIVE_TIME_30_MINUTES);
        session.setAttribute(AUTH_USER, user);
    }

    public static AppUser getAuthUser(HttpSession session) {
        return (AppUser) session.getAttribute(AUTH_USER);
    }

    public static void setUserAgent(HttpSession session, String userAgent) {
        session.setAttribute(USER_AGENT, userAgent);
    }

    public static void setTemporaryAuthUser(HttpSession session, AppUser user) {
        session.setAttribute(TEMPORARY_AUTH_USER, user);
    }

    public static AppUser getTemporaryAuthUser(HttpSession session) {
        return (AppUser) session.getAttribute(TEMPORARY_AUTH_USER);
    }

    public static void setOtpCode(HttpSession session, String otpCode) {
        session.setAttribute(OTP_CODE, otpCode);
    }

    public static String getOtpCode(HttpSession session) {
        return (String) session.getAttribute(OTP_CODE);
    }

    public static void setRememberMe(HttpSession session, Boolean rememberMe) {
        session.setAttribute(REMEMBER_ME, rememberMe);
    }

    public static boolean getRememberMe(HttpSession session) {
        return (Boolean) session.getAttribute(REMEMBER_ME);
    }

    public static void setGenerateLoginToken(HttpSession session, Boolean generateLoginToken) {
        session.setAttribute(GENERATE_LOGIN_TOKEN, generateLoginToken);
    }

    public static Boolean getGenerateLoginToken(HttpSession session) {
        return (Boolean) session.getAttribute(GENERATE_LOGIN_TOKEN);
    }

    public static void removeTemporaryInformation(HttpSession session) {
        session.removeAttribute(TEMPORARY_AUTH_USER);
        session.removeAttribute(OTP_CODE);
        session.removeAttribute(REMEMBER_ME);
        session.removeAttribute(GENERATE_LOGIN_TOKEN);
    }
}
