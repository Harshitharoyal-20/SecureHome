
package com.security.home.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "security_alerts")
public class SecurityAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "alert_id")
    private Integer alertId;

    @Column(name = "event_id")
    private Integer eventId;

    @Column(name = "recipient_user_id")
    private Integer recipientUserId;

    @Column(name = "severity")
    private String severity;

    @Column(name = "message")
    private String message;

    @Column(name = "status")
    private String status;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public Integer getAlertId() {
        return alertId;
    }

    public Integer getEventId() {
        return eventId;
    }

    public Integer getRecipientUserId() {
        return recipientUserId;
    }

    public String getSeverity() {
        return severity;
    }

    public String getMessage() {
        return message;
    }

    public String getStatus() {
        return status;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
}
