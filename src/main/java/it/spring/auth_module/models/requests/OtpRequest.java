package it.spring.auth_module.models.requests;

public record OtpRequest(String otpCode) {
    public boolean isNotValidRequest() {
        return otpCode == null;
    }
}
