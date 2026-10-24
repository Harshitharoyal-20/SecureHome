
package com.security.home.repository;

import com.security.home.entity.SecurityAlert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import java.util.List;

public interface SecurityAlertRepository
        extends JpaRepository<SecurityAlert, Integer> {

    List<SecurityAlert> findAllByOrderByCreatedAtDesc();

    @Query("SELECT s FROM SecurityAlert s WHERE UPPER(s.severity) = 'HIGH' OR UPPER(s.severity) = 'CRITICAL' OR UPPER(s.severity) LIKE '%HIGH%' ORDER BY s.createdAt DESC")
    List<SecurityAlert> findHighRiskAlerts();
}
