package it.spring.auth_module.models.requests;

public record TokenRequest(String token, boolean rememberMe) {
    public boolean isNotValidRequest() {
        return token == null;
    }
}
