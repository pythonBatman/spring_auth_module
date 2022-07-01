package it.spring.auth_module.models.repositories;

import it.spring.auth_module.models.AppToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AppTokenRepository extends JpaRepository<AppToken, Long> {
    Optional<AppToken> findAppTokenByToken(String token);
}
