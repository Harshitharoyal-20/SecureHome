
package com.security.home.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "access_events")
public class AccessEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "event_id")
    private Integer eventId;

    @Column(name = "user_id")
    private Integer userId;

    @Column(name = "asset_id")
    private Integer assetId;

    @Column(name = "event_time")
    private LocalDateTime eventTime;

    @Column(name = "decision")
    private String decision;

    @Column(name = "reason")
    private String reason;

    public Integer getEventId() {
        return eventId;
    }

    public Integer getUserId() {
        return userId;
    }

    public Integer getAssetId() {
        return assetId;
    }

    public LocalDateTime getEventTime() {
        return eventTime;
    }

    public String getDecision() {
        return decision;
    }

    public String getReason() {
        return reason;
    }
}
