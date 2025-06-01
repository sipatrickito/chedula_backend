"""
User Models for AI-Powered Appointment Scheduling System

This module defines the database models for user management, including
user profiles, subscription tracking, and authentication audit logging.
"""

import uuid
from django.db import models
from django.utils import timezone
from datetime import timedelta
from typing import Dict, Any, Optional


class UserProfile(models.Model):
    """
    Extended user profile linked to Supabase auth users.
    Stores business information, subscription details, and trial management.
    """
    
    # Subscription Plan Choices
    SUBSCRIPTION_PLANS = [
        ('freemium', 'Freemium'),
        ('basic', 'Basic'),
        ('professional', 'Professional'),
        ('enterprise', 'Enterprise'),
    ]
    
    # Subscription Status Choices
    SUBSCRIPTION_STATUS = [
        ('trialing', 'Trialing'),
        ('active', 'Active'),
        ('past_due', 'Past Due'),
        ('canceled', 'Canceled'),
        ('unpaid', 'Unpaid'),
        ('incomplete', 'Incomplete'),
        ('incomplete_expired', 'Incomplete Expired'),
        ('paused', 'Paused'),
    ]
    
    # Business Type Choices
    BUSINESS_TYPES = [
        ('camera_rental', 'Camera Rental'),
        ('equipment_rental', 'Equipment Rental'),
        ('professional_services', 'Professional Services'),
        ('consulting', 'Consulting'),
        ('beauty_wellness', 'Beauty & Wellness'),
        ('fitness_training', 'Fitness Training'),
        ('home_services', 'Home Services'),
        ('other', 'Other'),
    ]
    
    # Primary Fields
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.UUIDField(unique=True, db_index=True)  # Links to Supabase auth.users.id
    
    # Business Information
    business_name = models.CharField(max_length=255, blank=True)
    contact_email = models.EmailField(blank=True)
    phone_number = models.CharField(max_length=20, blank=True)
    business_address = models.TextField(blank=True)
    business_type = models.CharField(
        max_length=100, 
        choices=BUSINESS_TYPES,
        default='camera_rental'
    )
    business_description = models.TextField(blank=True)
    website_url = models.URLField(blank=True)
    
    # Subscription Management
    subscription_plan = models.CharField(
        max_length=50, 
        choices=SUBSCRIPTION_PLANS,
        default='freemium'
    )
    subscription_status = models.CharField(
        max_length=50, 
        choices=SUBSCRIPTION_STATUS,
        default='trialing'
    )
    subscription_start_date = models.DateTimeField(null=True, blank=True)
    subscription_end_date = models.DateTimeField(null=True, blank=True)
    
    # Trial Management
    trial_start_date = models.DateTimeField(default=timezone.now)
    trial_ends_at = models.DateTimeField()
    trial_extended = models.BooleanField(default=False)
    trial_extension_reason = models.TextField(blank=True)
    trial_extension_count = models.IntegerField(default=0)
    
    # Payment Integration
    paymongo_customer_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    stripe_customer_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    last_payment_date = models.DateTimeField(null=True, blank=True)
    next_billing_date = models.DateTimeField(null=True, blank=True)
    
    # Feature Usage Tracking
    monthly_bookings_used = models.IntegerField(default=0)
    monthly_bookings_limit = models.IntegerField(default=50)  # Freemium limit
    storage_used_mb = models.IntegerField(default=0)
    storage_limit_mb = models.IntegerField(default=100)  # Freemium limit
    
    # Settings and Preferences
    timezone = models.CharField(max_length=50, default='UTC')
    date_format = models.CharField(max_length=20, default='MM/DD/YYYY')
    time_format = models.CharField(max_length=10, default='12h')
    currency = models.CharField(max_length=3, default='USD')
    language = models.CharField(max_length=10, default='en')
    
    # Notification Preferences
    email_notifications = models.BooleanField(default=True)
    sms_notifications = models.BooleanField(default=False)
    marketing_emails = models.BooleanField(default=True)
    booking_reminders = models.BooleanField(default=True)
    
    # Account Status
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    is_onboarded = models.BooleanField(default=False)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'user_profiles'
        indexes = [
            models.Index(fields=['user_id']),
            models.Index(fields=['subscription_status']),
            models.Index(fields=['trial_ends_at']),
            models.Index(fields=['business_type']),
            models.Index(fields=['subscription_plan']),
            models.Index(fields=['created_at']),
        ]
        
    def __str__(self):
        return f"{self.business_name or self.contact_email or self.user_id}"
    
    def save(self, *args, **kwargs):
        # Set trial end date if not set
        if not self.trial_ends_at:
            self.trial_ends_at = self.trial_start_date + timedelta(days=7)
        
        # Update subscription limits based on plan
        self._update_subscription_limits()
        
        super().save(*args, **kwargs)
    
    def _update_subscription_limits(self):
        """Update usage limits based on subscription plan"""
        limits = {
            'freemium': {'bookings': 50, 'storage': 100},
            'basic': {'bookings': 200, 'storage': 1000},
            'professional': {'bookings': 1000, 'storage': 5000},
            'enterprise': {'bookings': -1, 'storage': -1},  # Unlimited
        }
        
        plan_limits = limits.get(self.subscription_plan, limits['freemium'])
        self.monthly_bookings_limit = plan_limits['bookings']
        self.storage_limit_mb = plan_limits['storage']
    
    @property
    def is_trial_active(self) -> bool:
        """Check if trial is still active"""
        return (
            self.subscription_status == 'trialing' and 
            self.trial_ends_at and 
            timezone.now() < self.trial_ends_at
        )
    
    @property
    def trial_days_remaining(self) -> int:
        """Get number of trial days remaining"""
        if not self.is_trial_active:
            return 0
        
        delta = self.trial_ends_at - timezone.now()
        return max(0, delta.days)
    
    @property
    def is_subscription_active(self) -> bool:
        """Check if subscription is active (including trial)"""
        active_statuses = ['trialing', 'active']
        return self.subscription_status in active_statuses
    
    @property
    def can_create_bookings(self) -> bool:
        """Check if user can create new bookings based on limits"""
        if not self.is_subscription_active:
            return False
        
        if self.monthly_bookings_limit == -1:  # Unlimited
            return True
        
        return self.monthly_bookings_used < self.monthly_bookings_limit
    
    @property
    def bookings_remaining(self) -> int:
        """Get number of bookings remaining this month"""
        if self.monthly_bookings_limit == -1:
            return -1  # Unlimited
        
        return max(0, self.monthly_bookings_limit - self.monthly_bookings_used)
    
    def extend_trial(self, days: int, reason: str = '') -> bool:
        """Extend trial period"""
        if self.trial_extension_count >= 2:  # Max 2 extensions
            return False
        
        self.trial_ends_at += timedelta(days=days)
        self.trial_extended = True
        self.trial_extension_reason = reason
        self.trial_extension_count += 1
        self.save(update_fields=[
            'trial_ends_at', 'trial_extended', 
            'trial_extension_reason', 'trial_extension_count'
        ])
        return True
    
    def reset_monthly_usage(self):
        """Reset monthly usage counters (called by billing cycle)"""
        self.monthly_bookings_used = 0
        self.save(update_fields=['monthly_bookings_used'])
    
    def increment_booking_usage(self):
        """Increment monthly booking usage"""
        self.monthly_bookings_used += 1
        self.save(update_fields=['monthly_bookings_used'])
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login_at = timezone.now()
        self.save(update_fields=['last_login_at'])


class AuthAuditLog(models.Model):
    """
    Authentication and security audit log.
    Tracks all authentication events and security-related activities.
    """
    
    # Action Type Choices
    ACTION_TYPES = [
        ('login_success', 'Login Success'),
        ('login_failed', 'Login Failed'),
        ('logout', 'Logout'),
        ('register', 'Register'),
        ('password_reset_request', 'Password Reset Request'),
        ('password_reset_success', 'Password Reset Success'),
        ('password_change', 'Password Change'),
        ('token_refresh', 'Token Refresh'),
        ('token_validation_failed', 'Token Validation Failed'),
        ('profile_update', 'Profile Update'),
        ('subscription_change', 'Subscription Change'),
        ('trial_extension', 'Trial Extension'),
        ('account_deactivation', 'Account Deactivation'),
        ('account_reactivation', 'Account Reactivation'),
        ('suspicious_activity', 'Suspicious Activity'),
        ('rate_limit_exceeded', 'Rate Limit Exceeded'),
        ('unauthorized_access_attempt', 'Unauthorized Access Attempt'),
    ]
    
    # Risk Level Choices
    RISK_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    # Primary Fields
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.UUIDField(null=True, blank=True, db_index=True)  # May be null for failed attempts
    
    # Event Details
    action = models.CharField(max_length=100, choices=ACTION_TYPES)
    success = models.BooleanField()
    failure_reason = models.CharField(max_length=255, blank=True)
    risk_level = models.CharField(max_length=10, choices=RISK_LEVELS, default='low')
    
    # Request Context
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    referer = models.URLField(blank=True)
    request_method = models.CharField(max_length=10, blank=True)
    request_path = models.CharField(max_length=500, blank=True)
    
    # Additional Context
    metadata = models.JSONField(default=dict, blank=True)  # Additional context data
    session_id = models.CharField(max_length=255, blank=True)
    
    # Geographic Information
    country = models.CharField(max_length=100, blank=True)
    region = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    
    # Timestamps
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    
    class Meta:
        db_table = 'auth_audit_logs'
        indexes = [
            models.Index(fields=['user_id', 'timestamp']),
            models.Index(fields=['action', 'success']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['risk_level', 'timestamp']),
            models.Index(fields=['success', 'timestamp']),
        ]
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.action} - {self.user_id or 'Anonymous'} - {self.timestamp}"
    
    @classmethod
    def log_event(cls, 
                  action: str, 
                  success: bool, 
                  user_id: Optional[str] = None,
                  ip_address: str = '',
                  user_agent: str = '',
                  failure_reason: str = '',
                  risk_level: str = 'low',
                  metadata: Optional[Dict[str, Any]] = None,
                  **kwargs) -> 'AuthAuditLog':
        """
        Convenience method to create audit log entries.
        """
        return cls.objects.create(
            action=action,
            success=success,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            failure_reason=failure_reason,
            risk_level=risk_level,
            metadata=metadata or {},
            **kwargs
        )
    
    @classmethod
    def get_failed_attempts(cls, ip_address: str, since_hours: int = 1) -> int:
        """Get count of failed login attempts from IP address in last N hours"""
        since_time = timezone.now() - timedelta(hours=since_hours)
        return cls.objects.filter(
            action__in=['login_failed', 'token_validation_failed'],
            ip_address=ip_address,
            timestamp__gte=since_time
        ).count()
    
    @classmethod
    def get_user_sessions(cls, user_id: str, days: int = 30):
        """Get user's authentication sessions in last N days"""
        since_time = timezone.now() - timedelta(days=days)
        return cls.objects.filter(
            user_id=user_id,
            action__in=['login_success', 'logout'],
            timestamp__gte=since_time
        ).order_by('-timestamp')


class UserSession(models.Model):
    """
    Track active user sessions for security and analytics.
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.UUIDField(db_index=True)
    
    # Session Details
    session_token = models.CharField(max_length=255, unique=True)
    refresh_token = models.CharField(max_length=255, blank=True)
    
    # Device Information
    device_type = models.CharField(max_length=50, blank=True)  # mobile, desktop, tablet
    browser = models.CharField(max_length=100, blank=True)
    operating_system = models.CharField(max_length=100, blank=True)
    
    # Location and Network
    ip_address = models.GenericIPAddressField()
    country = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    
    # Session Status
    is_active = models.BooleanField(default=True)
    last_activity = models.DateTimeField(auto_now=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    class Meta:
        db_table = 'user_sessions'
        indexes = [
            models.Index(fields=['user_id', 'is_active']),
            models.Index(fields=['session_token']),
            models.Index(fields=['expires_at', 'is_active']),
            models.Index(fields=['last_activity']),
        ]
    
    def __str__(self):
        return f"Session {self.session_token[:8]}... for {self.user_id}"
    
    @property
    def is_expired(self) -> bool:
        """Check if session is expired"""
        return timezone.now() > self.expires_at
    
    def extend_session(self, hours: int = 24):
        """Extend session expiration"""
        self.expires_at = timezone.now() + timedelta(hours=hours)
        self.save(update_fields=['expires_at'])
    
    def deactivate(self):
        """Deactivate session"""
        self.is_active = False
        self.save(update_fields=['is_active'])
    
    @classmethod
    def cleanup_expired_sessions(cls):
        """Remove expired sessions"""
        expired_sessions = cls.objects.filter(
            expires_at__lt=timezone.now()
        )
        count = expired_sessions.count()
        expired_sessions.delete()
        return count
