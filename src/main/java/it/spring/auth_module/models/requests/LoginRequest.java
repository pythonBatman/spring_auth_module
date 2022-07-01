package it.spring.auth_module.models.requests;

public record LoginRequest(String username, String password, boolean rememberMe, boolean generateLoginToken) {
    public boolean isNotValidRequest() {
        return username == null || password == null;
    }
}
