
package com.security.home.dto;

public class GuestAccessRequest {

    private Long guestPassId;
    private Long assetId;

    public Long getGuestPassId() {
        return guestPassId;
    }

    public void setGuestPassId(Long guestPassId) {
        this.guestPassId = guestPassId;
    }

    public Long getAssetId() {
        return assetId;
    }

    public void setAssetId(Long assetId) {
        this.assetId = assetId;
    }
}
