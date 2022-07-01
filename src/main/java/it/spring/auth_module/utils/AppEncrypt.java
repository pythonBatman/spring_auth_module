package it.spring.auth_module.utils;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class AppEncrypt {
    private static final Random random = new SecureRandom();
    private static final String saltCharacters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final String otpCharacters = "0123456789";
    private static final int saltLength = 32;
    private static final int otpLength = 5;
    private static final int iterations = 10000;
    private static final int keyLength = 256;

    private static byte[] hash(char[] password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        Arrays.fill(password, Character.MIN_VALUE);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new AssertionError("Error while hashing a password: " + e.getMessage(), e);
        } finally {
            spec.clearPassword();
        }
    }

    private static String randomGenerator(String charactersSet, int length) {
        StringBuilder value = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            value.append(charactersSet.charAt(random.nextInt(charactersSet.length())));
        }
        return new String(value);
    }

    public static String generateSalt() {
        return randomGenerator(saltCharacters, saltLength);
    }

    public static String generateOtpCode() {
        return randomGenerator(otpCharacters, otpLength);
    }

    public static String generateSecurePassword(String password, String salt) {
        byte[] securePassword = hash(password.toCharArray(), salt.getBytes());
        return Base64.getEncoder().encodeToString(securePassword);
    }

    public static boolean verifyPassword(String providedPassword, String securedPassword, String salt) {
        String newSecurePassword = generateSecurePassword(providedPassword, salt);
        return newSecurePassword.equalsIgnoreCase(securedPassword);
    }
}
