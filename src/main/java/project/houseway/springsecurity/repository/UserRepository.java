package project.houseway.springsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import project.houseway.springsecurity.domain.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUserid(String userid);
    boolean existsByUserid(String userid);
    boolean existsByEmail(String email);
}
