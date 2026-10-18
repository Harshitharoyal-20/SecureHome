
package com.security.home.repository;

import com.security.home.entity.SecureAsset;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface SecureAssetRepository
        extends JpaRepository<SecureAsset, Integer> {

    List<SecureAsset> findByStatus(String status);
}
