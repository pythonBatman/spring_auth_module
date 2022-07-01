package it.spring.auth_module.models.requests;

import java.time.LocalDate;

public record RegistrationRequest(String username, String password, String firstName, String lastName,
                                  LocalDate dateOfBirth, String phoneNumber) {
    public boolean isNotValidRequest() {
        return username == null || password == null || firstName == null || lastName == null || dateOfBirth == null;
    }
}
