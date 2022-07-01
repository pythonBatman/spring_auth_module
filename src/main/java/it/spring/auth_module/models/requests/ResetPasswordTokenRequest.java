package it.spring.auth_module.models.requests;

public record ResetPasswordTokenRequest(String token, String newPassword) {
    public boolean isNotValidRequest() {
        return token == null || newPassword == null;
    }
}
