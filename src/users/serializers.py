"""
Serializers for User Management

This module provides serializers for user profile data, subscription information,
trial status, and security-related data transfer.
"""

from rest_framework import serializers
from typing import Dict, Any
from .models import UserProfile, AuthAuditLog, UserSession


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile information.
    Handles business information, settings, and preferences.
    """
    
    # Computed fields
    is_trial_active = serializers.ReadOnlyField()
    trial_days_remaining = serializers.ReadOnlyField()
    is_subscription_active = serializers.ReadOnlyField()
    can_create_bookings = serializers.ReadOnlyField()
    bookings_remaining = serializers.ReadOnlyField()
    
    class Meta:
        model = UserProfile
        fields = [
            # Identity
            'id', 'user_id',
            
            # Business Information
            'business_name', 'contact_email', 'phone_number', 
            'business_address', 'business_type', 'business_description', 
            'website_url',
            
            # Subscription Information
            'subscription_plan', 'subscription_status',
            'subscription_start_date', 'subscription_end_date',
            
            # Trial Information
            'trial_start_date', 'trial_ends_at', 'trial_extended',
            'trial_extension_count', 'is_trial_active', 'trial_days_remaining',
            
            # Usage Statistics
            'monthly_bookings_used', 'monthly_bookings_limit',
            'storage_used_mb', 'storage_limit_mb',
            'can_create_bookings', 'bookings_remaining',
            
            # Settings and Preferences
            'timezone', 'date_format', 'time_format', 'currency', 'language',
            
            # Notification Preferences
            'email_notifications', 'sms_notifications', 
            'marketing_emails', 'booking_reminders',
            
            # Status
            'is_active', 'is_verified', 'is_onboarded', 'is_subscription_active',
            
            # Timestamps
            'created_at', 'updated_at', 'last_login_at'
        ]
        read_only_fields = [
            'id', 'user_id', 'created_at', 'updated_at', 'last_login_at',
            'subscription_plan', 'subscription_status', 'subscription_start_date',
            'subscription_end_date', 'trial_start_date', 'trial_ends_at',
            'trial_extended', 'trial_extension_count', 'monthly_bookings_used',
            'storage_used_mb', 'is_trial_active', 'trial_days_remaining',
            'can_create_bookings', 'bookings_remaining', 'is_subscription_active'
        ]
    
    def validate_business_type(self, value):
        """Validate business type is from allowed choices."""
        valid_types = [choice[0] for choice in UserProfile.BUSINESS_TYPES]
        if value not in valid_types:
            raise serializers.ValidationError(f"Invalid business type. Must be one of: {', '.join(valid_types)}")
        return value
    
    def validate_email(self, value):
        """Validate email format."""
        if value and '@' not in value:
            raise serializers.ValidationError("Enter a valid email address.")
        return value


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user profile information.
    More restrictive than the main serializer, only allows certain fields to be updated.
    """
    
    class Meta:
        model = UserProfile
        fields = [
            # Business Information (updatable)
            'business_name', 'contact_email', 'phone_number', 
            'business_address', 'business_type', 'business_description', 
            'website_url',
            
            # Settings and Preferences (updatable)
            'timezone', 'date_format', 'time_format', 'currency', 'language',
            
            # Notification Preferences (updatable)
            'email_notifications', 'sms_notifications', 
            'marketing_emails', 'booking_reminders',
        ]
    
    def validate_business_type(self, value):
        """Validate business type is from allowed choices."""
        valid_types = [choice[0] for choice in UserProfile.BUSINESS_TYPES]
        if value not in valid_types:
            raise serializers.ValidationError(f"Invalid business type. Must be one of: {', '.join(valid_types)}")
        return value


class SubscriptionStatusSerializer(serializers.ModelSerializer):
    """
    Serializer for subscription status and trial information.
    """
    
    # Computed fields
    is_trial_active = serializers.ReadOnlyField()
    trial_days_remaining = serializers.ReadOnlyField()
    is_subscription_active = serializers.ReadOnlyField()
    
    class Meta:
        model = UserProfile
        fields = [
            # Subscription Information
            'subscription_plan', 'subscription_status',
            'subscription_start_date', 'subscription_end_date',
            'next_billing_date',
            
            # Trial Information
            'trial_start_date', 'trial_ends_at', 'trial_extended',
            'trial_extension_count', 'is_trial_active', 'trial_days_remaining',
            
            # Computed Status
            'is_subscription_active',
        ]
        read_only_fields = [
            'subscription_plan', 'subscription_status', 'subscription_start_date',
            'subscription_end_date', 'next_billing_date', 'trial_start_date', 
            'trial_ends_at', 'trial_extended', 'trial_extension_count',
            'is_trial_active', 'trial_days_remaining', 'is_subscription_active'
        ]


class UsageStatsSerializer(serializers.ModelSerializer):
    """
    Serializer for usage statistics and limits.
    """
    
    # Computed fields
    can_create_bookings = serializers.ReadOnlyField()
    bookings_remaining = serializers.ReadOnlyField()
    
    class Meta:
        model = UserProfile
        fields = [
            # Usage Statistics
            'monthly_bookings_used', 'monthly_bookings_limit',
            'storage_used_mb', 'storage_limit_mb',
            
            # Computed Fields
            'can_create_bookings', 'bookings_remaining',
            
            # Plan Information
            'subscription_plan', 'subscription_status',
        ]
        read_only_fields = [
            'monthly_bookings_used', 'monthly_bookings_limit',
            'storage_used_mb', 'storage_limit_mb',
            'can_create_bookings', 'bookings_remaining',
            'subscription_plan', 'subscription_status'
        ]


class AuthAuditLogSerializer(serializers.ModelSerializer):
    """
    Serializer for authentication audit log entries.
    """
    
    class Meta:
        model = AuthAuditLog
        fields = [
            'id', 'user_id', 'action', 'success', 'failure_reason',
            'risk_level', 'ip_address', 'user_agent', 'referer',
            'request_method', 'request_path', 'metadata',
            'country', 'region', 'city', 'timestamp'
        ]
        read_only_fields = '__all__'


class UserSessionSerializer(serializers.ModelSerializer):
    """
    Serializer for user session information.
    """
    
    # Computed fields
    is_expired = serializers.ReadOnlyField()
    
    class Meta:
        model = UserSession
        fields = [
            'id', 'user_id', 'device_type', 'browser', 'operating_system',
            'ip_address', 'country', 'city', 'is_active', 'last_activity',
            'created_at', 'expires_at', 'is_expired'
        ]
        read_only_fields = [
            'id', 'user_id', 'device_type', 'browser', 'operating_system',
            'ip_address', 'country', 'city', 'last_activity',
            'created_at', 'expires_at', 'is_expired'
        ]


class BusinessTypeChoicesSerializer(serializers.Serializer):
    """
    Serializer for business type choices.
    """
    value = serializers.CharField()
    label = serializers.CharField()


class UserOnboardingSerializer(serializers.Serializer):
    """
    Serializer for user onboarding process.
    """
    business_name = serializers.CharField(max_length=255, required=True)
    business_type = serializers.ChoiceField(choices=UserProfile.BUSINESS_TYPES, required=True)
    contact_email = serializers.EmailField(required=False, allow_blank=True)
    phone_number = serializers.CharField(max_length=20, required=False, allow_blank=True)
    business_address = serializers.CharField(required=False, allow_blank=True)
    timezone = serializers.CharField(max_length=50, required=False, default='UTC')
    
    def validate_business_name(self, value):
        """Validate business name is not empty."""
        if not value.strip():
            raise serializers.ValidationError("Business name cannot be empty.")
        return value.strip()


class TrialExtensionSerializer(serializers.Serializer):
    """
    Serializer for trial extension requests (admin only).
    """
    user_id = serializers.UUIDField(required=True)
    days = serializers.IntegerField(min_value=1, max_value=30, required=True)
    reason = serializers.CharField(max_length=500, required=True)
    
    def validate_days(self, value):
        """Validate extension days."""
        if value <= 0:
            raise serializers.ValidationError("Extension days must be positive.")
        if value > 30:
            raise serializers.ValidationError("Cannot extend trial by more than 30 days at once.")
        return value
    
    def validate_reason(self, value):
        """Validate extension reason."""
        if not value.strip():
            raise serializers.ValidationError("Extension reason is required.")
        return value.strip()


class SecurityReportSerializer(serializers.Serializer):
    """
    Serializer for security reports and statistics.
    """
    total_logins = serializers.IntegerField(read_only=True)
    failed_attempts = serializers.IntegerField(read_only=True)
    unique_ips = serializers.IntegerField(read_only=True)
    suspicious_activities = serializers.IntegerField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True)
    active_sessions = serializers.IntegerField(read_only=True)
    recent_events = AuthAuditLogSerializer(many=True, read_only=True)


class UserStatsSerializer(serializers.Serializer):
    """
    Serializer for comprehensive user statistics.
    """
    profile = UserProfileSerializer(read_only=True)
    subscription = SubscriptionStatusSerializer(read_only=True)
    usage = UsageStatsSerializer(read_only=True)
    security = SecurityReportSerializer(read_only=True)


class ErrorResponseSerializer(serializers.Serializer):
    """
    Serializer for standardized error responses.
    """
    error = serializers.CharField()
    message = serializers.CharField()
    details = serializers.DictField(required=False)
    timestamp = serializers.DateTimeField()


class SuccessResponseSerializer(serializers.Serializer):
    """
    Serializer for standardized success responses.
    """
    success = serializers.BooleanField(default=True)
    message = serializers.CharField()
    data = serializers.DictField(required=False) 