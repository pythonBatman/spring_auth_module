package it.spring.auth_module.models;

import it.spring.auth_module.auth.roles.AuthRoles;
import it.spring.auth_module.models.requests.RegistrationRequest;
import it.spring.auth_module.utils.AppEncrypt;
import lombok.*;
import org.hibernate.Hibernate;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Objects;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Entity(name = "app_user")
public class AppUser {
    @SequenceGenerator(name = "app_user_sequence", sequenceName = "app_user_sequence", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "app_user_sequence")
    @Id
    private Long id;
    @Column(nullable = false, unique = true)
    private String username;
    @Column(nullable = false)
    private String password;
    @Column(nullable = false)
    private String firstName;
    @Column(nullable = false)
    private String lastName;
    @Column(nullable = false)
    private LocalDate dateOfBirth;
    private String phoneNumber;
    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private AuthRoles.Roles role;
    @Column(nullable = false)
    private String passwordSalt;
    private LocalDateTime enabledAt;
    private LocalDateTime lockedAt;
    @Column(nullable = false)
    private LocalDateTime changedPasswordAt;
    @Column(nullable = false)
    private LocalDateTime createdAt;
    @Column(nullable = false)
    private LocalDateTime updatedAt;

    public AppUser(RegistrationRequest request) {
        this.username = request.username().toLowerCase();
        this.firstName = request.firstName();
        this.lastName = request.lastName();
        this.dateOfBirth = request.dateOfBirth();
        this.phoneNumber = request.phoneNumber();
        this.passwordSalt = AppEncrypt.generateSalt();
        this.password = AppEncrypt.generateSecurePassword(request.password(), passwordSalt);
        this.createdAt = LocalDateTime.now();
        this.updatedAt = createdAt;
        this.changedPasswordAt = createdAt;
    }

    public boolean verifyPassword(String providedPassword) {
        return AppEncrypt.verifyPassword(providedPassword, password, passwordSalt);
    }

    public boolean isIncorrectPassword(String providedPassword) {
        return !AppEncrypt.verifyPassword(providedPassword, password, passwordSalt);
    }

    public boolean isEnabled() {
        return enabledAt != null;
    }

    public boolean isNotEnabled() {
        return enabledAt == null;
    }

    public boolean isLocked() {
        return lockedAt != null;
    }

    public boolean needToChangePassword() {
        return changedPasswordAt.plusMonths(6).isBefore(LocalDateTime.now());
    }

    public Map<String, Object> getPublicData() {
        return getPublicData(null);
    }

    public Map<String, Object> getPublicData(String loginToken) {
        return Map.of(
                "id", id,
                "username", username,
                "firstName", firstName,
                "lastName", lastName,
                "dateOfBirth", dateOfBirth,
                "role", role,
                "phoneNumber", phoneNumber != null ? phoneNumber : "",
                "loginToken", loginToken != null ? loginToken : ""
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || Hibernate.getClass(this) != Hibernate.getClass(o)) return false;
        AppUser user = (AppUser) o;
        return id != null && Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
