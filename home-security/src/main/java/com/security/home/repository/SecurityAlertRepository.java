
package com.security.home.repository;

import com.security.home.entity.SecurityAlert;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface SecurityAlertRepository
        extends JpaRepository<SecurityAlert, Integer> {

    List<SecurityAlert> findAllByOrderByCreatedAtDesc();
}
