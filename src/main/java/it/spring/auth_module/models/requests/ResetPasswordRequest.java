package it.spring.auth_module.models.requests;

public record ResetPasswordRequest(String username) {
    public boolean isNotValidRequest() {
        return username == null;
    }
}
