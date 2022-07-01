package it.spring.auth_module.models;

import lombok.*;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Entity(name = "app_token")
public class AppToken {
    public enum Type {confirmation, login, resetPassword}

    @SequenceGenerator(name = "app_token_sequence", sequenceName = "app_token_sequence", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "app_token_sequence")
    @Id
    private Long id;
    @Column(nullable = false, unique = true)
    private String token;
    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Type type;
    @ManyToOne
    @JoinColumn(nullable = false, name = "app_user_id")
    private AppUser appUser;
    @Column(nullable = false)
    private int requestTimes;
    @Column(nullable = false)
    private LocalDateTime createdAt;
    @Column(nullable = false)
    private LocalDateTime updatedAt;

    public AppToken(AppUser appUser, Type type) {
        this.token = UUID.randomUUID().toString();
        this.appUser = appUser;
        this.type = type;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = createdAt;
    }

    private LocalDateTime getExpirationTime() {
        return switch (type) {
            case confirmation, resetPassword -> createdAt.plusDays(1);
            case login -> updatedAt.plusMonths(6);
        };
    }

    private boolean hasBeenUsed() {
        return switch (type) {
            case confirmation, resetPassword -> requestTimes > 0;
            case login -> false;
        };
    }

    public boolean isExpired() {
        return getExpirationTime().isBefore(LocalDateTime.now()) || hasBeenUsed();
    }

    public boolean isNotLoginToken() {
        return !type.equals(Type.login);
    }
}
