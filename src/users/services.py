"""
User Profile Services for AI-Powered Appointment Scheduling System

This module provides business logic services for user profile management,
subscription handling, and user-related operations.
"""

import logging
from typing import Optional, Dict, Any, List
from django.utils import timezone
from django.db import transaction
from django.core.exceptions import ValidationError
from .models import UserProfile, AuthAuditLog, UserSession

logger = logging.getLogger(__name__)


class UserProfileService:
    """
    Service class for managing user profiles and related operations.
    Handles profile creation, updates, subscription management, and trial handling.
    """
    
    def get_or_create_profile(self, 
                            user_id: str, 
                            email: str = '', 
                            user_metadata: Optional[Dict[str, Any]] = None) -> UserProfile:
        """
        Get existing user profile or create a new one.
        This is called during authentication to ensure profile exists.
        """
        try:
            # Try to get existing profile
            profile = UserProfile.objects.get(user_id=user_id)
            
            # Update last login
            profile.update_last_login()
            
            return profile
            
        except UserProfile.DoesNotExist:
            # Create new profile with trial
            return self.create_profile(user_id, email, user_metadata)
    
    def create_profile(self, 
                      user_id: str, 
                      email: str = '', 
                      user_metadata: Optional[Dict[str, Any]] = None) -> UserProfile:
        """
        Create a new user profile with 7-day trial.
        """
        user_metadata = user_metadata or {}
        
        try:
            with transaction.atomic():
                # Create profile with trial
                profile = UserProfile.objects.create(
                    user_id=user_id,
                    contact_email=email,
                    business_name=user_metadata.get('business_name', ''),
                    business_type=user_metadata.get('business_type', 'camera_rental'),
                    subscription_status='trialing',
                    trial_start_date=timezone.now(),
                    is_active=True,
                )
                
                # Log profile creation
                AuthAuditLog.log_event(
                    action='register',
                    success=True,
                    user_id=user_id,
                    ip_address='0.0.0.0',
                    metadata={
                        'business_type': profile.business_type,
                        'trial_end_date': profile.trial_ends_at.isoformat()
                    }
                )
                
                logger.info(f"Created new user profile for {user_id} with 7-day trial")
                
                return profile
                
        except Exception as e:
            logger.error(f"Failed to create profile for user {user_id}: {e}")
            raise ValidationError(f"Failed to create user profile: {e}")
    
    def get_profile(self, user_id: str) -> Optional[UserProfile]:
        """Get user profile by user ID."""
        try:
            return UserProfile.objects.get(user_id=user_id)
        except UserProfile.DoesNotExist:
            return None
    
    def update_profile(self, 
                      user_id: str, 
                      profile_data: Dict[str, Any],
                      ip_address: str = '',
                      user_agent: str = '') -> UserProfile:
        """
        Update user profile information.
        """
        try:
            profile = UserProfile.objects.get(user_id=user_id)
            
            # Track what fields are being updated
            updated_fields = []
            
            # Business information updates
            business_fields = [
                'business_name', 'contact_email', 'phone_number', 
                'business_address', 'business_type', 'business_description', 
                'website_url'
            ]
            
            for field in business_fields:
                if field in profile_data:
                    setattr(profile, field, profile_data[field])
                    updated_fields.append(field)
            
            # Settings and preferences
            settings_fields = [
                'timezone', 'date_format', 'time_format', 'currency', 'language'
            ]
            
            for field in settings_fields:
                if field in profile_data:
                    setattr(profile, field, profile_data[field])
                    updated_fields.append(field)
            
            # Notification preferences
            notification_fields = [
                'email_notifications', 'sms_notifications', 
                'marketing_emails', 'booking_reminders'
            ]
            
            for field in notification_fields:
                if field in profile_data:
                    setattr(profile, field, profile_data[field])
                    updated_fields.append(field)
            
            # Status fields (like is_onboarded)
            status_fields = ['is_onboarded', 'is_verified']
            
            for field in status_fields:
                if field in profile_data:
                    setattr(profile, field, profile_data[field])
                    updated_fields.append(field)
            
            # Save changes
            profile.save()
            
            # Log profile update
            AuthAuditLog.log_event(
                action='profile_update',
                success=True,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                metadata={
                    'updated_fields': updated_fields,
                    'business_name': profile.business_name
                }
            )
            
            logger.info(f"Updated profile for user {user_id}: {updated_fields}")
            
            return profile
            
        except UserProfile.DoesNotExist:
            raise ValidationError("User profile not found")
        except Exception as e:
            logger.error(f"Failed to update profile for user {user_id}: {e}")
            raise ValidationError(f"Failed to update profile: {e}")
    
    def deactivate_profile(self, 
                          user_id: str,
                          reason: str = '',
                          ip_address: str = '',
                          user_agent: str = '') -> bool:
        """
        Deactivate user profile and log the action.
        """
        try:
            profile = UserProfile.objects.get(user_id=user_id)
            profile.is_active = False
            profile.save(update_fields=['is_active'])
            
            # Log deactivation
            AuthAuditLog.log_event(
                action='account_deactivation',
                success=True,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                metadata={'reason': reason}
            )
            
            logger.info(f"Deactivated profile for user {user_id}: {reason}")
            
            return True
            
        except UserProfile.DoesNotExist:
            logger.warning(f"Attempted to deactivate non-existent profile: {user_id}")
            return False
        except Exception as e:
            logger.error(f"Failed to deactivate profile for user {user_id}: {e}")
            return False
    
    def extend_trial(self, 
                    user_id: str, 
                    days: int, 
                    reason: str = '',
                    admin_user_id: str = '') -> bool:
        """
        Extend user trial period (admin operation).
        """
        try:
            profile = UserProfile.objects.get(user_id=user_id)
            
            if profile.extend_trial(days, reason):
                # Log trial extension
                AuthAuditLog.log_event(
                    action='trial_extension',
                    success=True,
                    user_id=user_id,
                    metadata={
                        'days_extended': days,
                        'reason': reason,
                        'admin_user_id': admin_user_id,
                        'new_trial_end': profile.trial_ends_at.isoformat()
                    }
                )
                
                logger.info(f"Extended trial for user {user_id} by {days} days: {reason}")
                return True
            else:
                logger.warning(f"Failed to extend trial for user {user_id}: maximum extensions reached")
                return False
                
        except UserProfile.DoesNotExist:
            logger.warning(f"Attempted to extend trial for non-existent profile: {user_id}")
            return False
        except Exception as e:
            logger.error(f"Failed to extend trial for user {user_id}: {e}")
            return False
    
    def update_subscription(self, 
                           user_id: str, 
                           plan: str, 
                           status: str,
                           payment_data: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update user subscription plan and status.
        """
        try:
            profile = UserProfile.objects.get(user_id=user_id)
            
            old_plan = profile.subscription_plan
            old_status = profile.subscription_status
            
            # Update subscription
            profile.subscription_plan = plan
            profile.subscription_status = status
            
            if payment_data:
                if 'customer_id' in payment_data:
                    profile.paymongo_customer_id = payment_data['customer_id']
                if 'next_billing_date' in payment_data:
                    profile.next_billing_date = payment_data['next_billing_date']
                if 'subscription_start_date' in payment_data:
                    profile.subscription_start_date = payment_data['subscription_start_date']
            
            profile.save()
            
            # Log subscription change
            AuthAuditLog.log_event(
                action='subscription_change',
                success=True,
                user_id=user_id,
                metadata={
                    'old_plan': old_plan,
                    'new_plan': plan,
                    'old_status': old_status,
                    'new_status': status,
                    'payment_data': payment_data or {}
                }
            )
            
            logger.info(f"Updated subscription for user {user_id}: {old_plan} -> {plan}, {old_status} -> {status}")
            
            return True
            
        except UserProfile.DoesNotExist:
            logger.warning(f"Attempted to update subscription for non-existent profile: {user_id}")
            return False
        except Exception as e:
            logger.error(f"Failed to update subscription for user {user_id}: {e}")
            return False
    
    def get_trial_status(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get trial status information for a user.
        """
        try:
            profile = UserProfile.objects.get(user_id=user_id)
            
            return {
                'is_trial_active': profile.is_trial_active,
                'trial_days_remaining': profile.trial_days_remaining,
                'trial_start_date': profile.trial_start_date,
                'trial_ends_at': profile.trial_ends_at,
                'trial_extended': profile.trial_extended,
                'trial_extension_count': profile.trial_extension_count,
                'subscription_plan': profile.subscription_plan,
                'subscription_status': profile.subscription_status,
            }
            
        except UserProfile.DoesNotExist:
            return None
    
    def get_usage_stats(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get usage statistics for a user.
        """
        try:
            profile = UserProfile.objects.get(user_id=user_id)
            
            return {
                'monthly_bookings_used': profile.monthly_bookings_used,
                'monthly_bookings_limit': profile.monthly_bookings_limit,
                'bookings_remaining': profile.bookings_remaining,
                'can_create_bookings': profile.can_create_bookings,
                'storage_used_mb': profile.storage_used_mb,
                'storage_limit_mb': profile.storage_limit_mb,
                'subscription_plan': profile.subscription_plan,
                'subscription_status': profile.subscription_status,
            }
            
        except UserProfile.DoesNotExist:
            return None
    
    def increment_booking_usage(self, user_id: str) -> bool:
        """
        Increment booking usage for a user.
        """
        try:
            profile = UserProfile.objects.get(user_id=user_id)
            profile.increment_booking_usage()
            return True
        except UserProfile.DoesNotExist:
            return False
    
    def get_profiles_by_business_type(self, business_type: str) -> List[UserProfile]:
        """
        Get all profiles for a specific business type.
        """
        return UserProfile.objects.filter(
            business_type=business_type,
            is_active=True
        ).order_by('-created_at')
    
    def get_expiring_trials(self, days_ahead: int = 3) -> List[UserProfile]:
        """
        Get trials that are expiring within specified days.
        """
        expiry_date = timezone.now() + timezone.timedelta(days=days_ahead)
        
        return UserProfile.objects.filter(
            subscription_status='trialing',
            trial_ends_at__lte=expiry_date,
            trial_ends_at__gt=timezone.now(),
            is_active=True
        ).order_by('trial_ends_at')


class SecurityService:
    """
    Service class for security-related operations and audit logging.
    """
    
    @staticmethod
    def log_authentication_event(action: str,
                                success: bool,
                                user_id: Optional[str] = None,
                                request = None,
                                failure_reason: str = '',
                                metadata: Optional[Dict[str, Any]] = None) -> AuthAuditLog:
        """
        Log an authentication event with request context.
        """
        ip_address = ''
        user_agent = ''
        referer = ''
        request_method = ''
        request_path = ''
        
        if request:
            # Extract request information
            ip_address = SecurityService.get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]  # Limit length
            referer = request.META.get('HTTP_REFERER', '')
            request_method = request.method
            request_path = request.path
        
        return AuthAuditLog.log_event(
            action=action,
            success=success,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            referer=referer,
            request_method=request_method,
            request_path=request_path,
            failure_reason=failure_reason,
            metadata=metadata or {}
        )
    
    @staticmethod
    def get_client_ip(request) -> str:
        """
        Get client IP address from request, handling proxies.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip or ''
    
    @staticmethod
    def check_rate_limit(ip_address: str, action: str = 'login_failed', 
                        limit: int = 5, window_hours: int = 1) -> bool:
        """
        Check if IP address has exceeded rate limit for failed attempts.
        Returns True if rate limit exceeded.
        """
        attempts = AuthAuditLog.get_failed_attempts(ip_address, window_hours)
        return attempts >= limit
    
    @staticmethod
    def get_user_security_events(user_id: str, days: int = 30) -> List[AuthAuditLog]:
        """
        Get security events for a user in the last N days.
        """
        since_time = timezone.now() - timezone.timedelta(days=days)
        return AuthAuditLog.objects.filter(
            user_id=user_id,
            timestamp__gte=since_time
        ).order_by('-timestamp')
    
    @staticmethod
    def detect_suspicious_activity(user_id: str) -> List[Dict[str, Any]]:
        """
        Analyze user activity to detect potential security issues.
        """
        suspicious_events = []
        
        # Check for multiple failed login attempts
        recent_failures = AuthAuditLog.objects.filter(
            user_id=user_id,
            action='login_failed',
            timestamp__gte=timezone.now() - timezone.timedelta(hours=24)
        ).count()
        
        if recent_failures >= 3:
            suspicious_events.append({
                'type': 'multiple_failed_logins',
                'severity': 'medium',
                'count': recent_failures,
                'description': f'{recent_failures} failed login attempts in last 24 hours'
            })
        
        # Check for logins from multiple IPs
        recent_logins = AuthAuditLog.objects.filter(
            user_id=user_id,
            action='login_success',
            timestamp__gte=timezone.now() - timezone.timedelta(hours=24)
        ).values_list('ip_address', flat=True).distinct()
        
        if len(recent_logins) > 3:
            suspicious_events.append({
                'type': 'multiple_ip_logins',
                'severity': 'high',
                'count': len(recent_logins),
                'description': f'Logins from {len(recent_logins)} different IPs in last 24 hours'
            })
        
        return suspicious_events


class SessionService:
    """
    Service class for managing user sessions.
    """
    
    @staticmethod
    def create_session(user_id: str, 
                      session_token: str,
                      request = None,
                      expires_hours: int = 24) -> UserSession:
        """
        Create a new user session.
        """
        ip_address = ''
        user_agent = ''
        
        if request:
            ip_address = SecurityService.get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        return UserSession.objects.create(
            user_id=user_id,
            session_token=session_token,
            ip_address=ip_address,
            expires_at=timezone.now() + timezone.timedelta(hours=expires_hours)
        )
    
    @staticmethod
    def get_active_sessions(user_id: str) -> List[UserSession]:
        """
        Get all active sessions for a user.
        """
        return UserSession.objects.filter(
            user_id=user_id,
            is_active=True,
            expires_at__gt=timezone.now()
        ).order_by('-last_activity')
    
    @staticmethod
    def deactivate_session(session_token: str) -> bool:
        """
        Deactivate a specific session.
        """
        try:
            session = UserSession.objects.get(session_token=session_token)
            session.deactivate()
            return True
        except UserSession.DoesNotExist:
            return False
    
    @staticmethod
    def cleanup_expired_sessions() -> int:
        """
        Remove expired sessions from database.
        """
        return UserSession.cleanup_expired_sessions() 