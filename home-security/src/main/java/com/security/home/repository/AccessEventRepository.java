
package com.security.home.repository;

import com.security.home.entity.AccessEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface AccessEventRepository
        extends JpaRepository<AccessEvent, Integer> {

    List<AccessEvent> findAllByOrderByEventTimeDesc();

    List<AccessEvent> findByUserIdOrderByEventTimeDesc(
            Integer userId);
}
