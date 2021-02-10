package me.hailey.jwhTutorial.repository;

import me.hailey.jwhTutorial.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    //User Entity에 매핑되는 UserRepository 인터페이스
    @EntityGraph(attributePaths = "authorities") //EntityGraph -> Lazy가 아닌 Eager조회로 authorities를 가져옴
    Optional<User> findOneWithAuthoritiesByUsername(String username);

}
