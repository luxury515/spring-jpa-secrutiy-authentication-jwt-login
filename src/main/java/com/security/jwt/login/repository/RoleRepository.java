package com.security.jwt.login.repository;

import com.security.jwt.login.entity.Role;
import com.security.jwt.login.enums.RoleCode;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role,Integer> {
    Optional<Role> findByName(RoleCode roleCode);
}
