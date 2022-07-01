package it.spring.auth_module.models.requests;

public record ChangePasswordRequest(String username, String currentPassword, String newPassword) {
    public boolean isNotValidRequest() {
        return username == null || currentPassword == null || newPassword == null;
    }
}
