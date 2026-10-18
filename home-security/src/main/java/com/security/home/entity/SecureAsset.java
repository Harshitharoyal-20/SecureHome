
package com.security.home.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@Entity
@Table(name = "secure_assets")
public class SecureAsset {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "asset_id")
    private Integer assetId;

    @NotBlank(message = "Asset name is required")
    @Size(max = 100, message = "Asset name must not exceed 100 characters")
    @Column(name = "asset_name")
    private String assetName;

    @NotBlank(message = "Asset type is required")
    @Pattern(regexp = "LOCKER|SAFE", flags = Pattern.Flag.CASE_INSENSITIVE,
             message = "Type must be LOCKER or SAFE")
    @Column(name = "asset_type")
    private String assetType;

    @NotBlank(message = "Location is required")
    @Size(max = 255, message = "Location must not exceed 255 characters")
    @Column(name = "location_description")
    private String locationDescription;

    @Column(name = "owner_user_id")
    private Integer ownerUserId;

    @NotBlank(message = "Status is required")
    @Pattern(regexp = "ACTIVE|INACTIVE", flags = Pattern.Flag.CASE_INSENSITIVE,
             message = "Status must be ACTIVE or INACTIVE")
    @Column(name = "status")
    private String status;

    public Integer getAssetId() {
        return assetId;
    }

    public String getAssetName() {
        return assetName;
    }

    public void setAssetName(String assetName) {
        this.assetName = assetName;
    }

    public String getAssetType() {
        return assetType;
    }

    public void setAssetType(String assetType) {
        this.assetType = assetType;
    }

    public String getLocationDescription() {
        return locationDescription;
    }

    public void setLocationDescription(String locationDescription) {
        this.locationDescription = locationDescription;
    }

    public Integer getOwnerUserId() {
        return ownerUserId;
    }

    public void setOwnerUserId(Integer ownerUserId) {
        this.ownerUserId = ownerUserId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
