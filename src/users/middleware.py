"""
Middleware for AI-Powered Appointment Scheduling System

This module provides middleware classes for authentication integration,
audit logging, and security monitoring.
"""

import logging
import time
from typing import Optional
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.core.cache import cache
from .authentication import SupabaseJWTAuthentication, SupabaseUser
from .services import SecurityService, UserProfileService
from .models import AuthAuditLog

logger = logging.getLogger(__name__)


class SupabaseAuthMiddleware(MiddlewareMixin):
    """
    Middleware to integrate Supabase authentication with Django request processing.
    Automatically validates JWT tokens and attaches user information to requests.
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.auth_backend = SupabaseJWTAuthentication()
        self.user_service = UserProfileService()
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process incoming request to validate authentication and attach user info.
        """
        # Skip authentication for certain paths
        if self._should_skip_auth(request.path):
            return None
        
        # Try to authenticate the request
        try:
            auth_result = self.auth_backend.authenticate(request)
            
            if auth_result:
                user, token = auth_result
                request.user = user
                request.auth = token
                
                # Attach user profile for easy access
                if hasattr(user, 'profile'):
                    request.user_profile = user.profile
                else:
                    # Try to get profile if not attached during auth
                    profile = self.user_service.get_profile(user.id)
                    request.user_profile = profile
                    user.profile = profile
                
                # Log successful authentication (rate limited to avoid spam)
                self._log_successful_auth(request, user.id)
                
            else:
                # No authentication provided - this is fine for public endpoints
                request.user = None
                request.auth = None
                request.user_profile = None
                
        except Exception as e:
            # Authentication failed
            logger.warning(f"Authentication failed for {request.path}: {e}")
            
            # Log failed authentication attempt
            SecurityService.log_authentication_event(
                action='token_validation_failed',
                success=False,
                request=request,
                failure_reason=str(e)
            )
            
            # For API endpoints, return 401
            if request.path.startswith('/api/'):
                return JsonResponse(
                    {'error': 'Invalid authentication credentials'}, 
                    status=401
                )
            
            # For other endpoints, let the view handle it
            request.user = None
            request.auth = None
            request.user_profile = None
        
        return None
    
    def _should_skip_auth(self, path: str) -> bool:
        """
        Determine if authentication should be skipped for this path.
        """
        # Skip auth for these paths
        skip_paths = [
            '/admin/',
            '/health/',
            '/api/v1/health/',
            '/public/',
            '/static/',
            '/media/',
        ]
        
        for skip_path in skip_paths:
            if path.startswith(skip_path):
                return True
        
        return False
    
    def _log_successful_auth(self, request: HttpRequest, user_id: str):
        """
        Log successful authentication with rate limiting to avoid spam.
        """
        # Use cache to rate limit auth logging (max once per minute per user)
        cache_key = f"auth_log:{user_id}"
        if not cache.get(cache_key):
            SecurityService.log_authentication_event(
                action='login_success',
                success=True,
                user_id=user_id,
                request=request
            )
            # Cache for 60 seconds
            cache.set(cache_key, True, 60)


class AuditLoggingMiddleware(MiddlewareMixin):
    """
    Middleware for comprehensive audit logging of user actions and security events.
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.security_service = SecurityService()
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process request to check for rate limiting and security issues.
        """
        # Check rate limiting for authentication endpoints
        if self._is_auth_endpoint(request.path):
            ip_address = SecurityService.get_client_ip(request)
            
            # Check if IP is rate limited
            if SecurityService.check_rate_limit(ip_address, limit=10, window_hours=1):
                logger.warning(f"Rate limit exceeded for IP {ip_address} on {request.path}")
                
                # Log rate limit event
                AuthAuditLog.log_event(
                    action='rate_limit_exceeded',
                    success=False,
                    ip_address=ip_address,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    request_method=request.method,
                    request_path=request.path,
                    failure_reason='Too many requests',
                    risk_level='medium'
                )
                
                return JsonResponse(
                    {'error': 'Too many requests. Please try again later.'}, 
                    status=429
                )
        
        # Store request start time for performance logging
        request._audit_start_time = time.time()
        
        return None
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Process response to log relevant user actions and security events.
        """
        # Calculate request duration
        start_time = getattr(request, '_audit_start_time', time.time())
        duration = time.time() - start_time
        
        # Log significant actions based on path and method
        self._log_user_action(request, response, duration)
        
        # Monitor for suspicious patterns
        self._monitor_security_patterns(request, response)
        
        return response
    
    def _is_auth_endpoint(self, path: str) -> bool:
        """Check if path is an authentication-related endpoint."""
        auth_paths = [
            '/api/v1/auth/',
            '/api/v1/users/profile/',
            '/api/v1/users/subscription/',
        ]
        
        for auth_path in auth_paths:
            if path.startswith(auth_path):
                return True
        
        return False
    
    def _log_user_action(self, request: HttpRequest, response: HttpResponse, duration: float):
        """
        Log significant user actions based on request details.
        """
        # Only log certain types of actions
        should_log = False
        action = ''
        risk_level = 'low'
        
        # Determine if we should log this action
        if request.method in ['POST', 'PUT', 'DELETE']:
            should_log = True
            
            # Determine action type
            if '/profile/' in request.path:
                action = 'profile_update'
            elif '/subscription/' in request.path:
                action = 'subscription_change'
                risk_level = 'medium'
            elif '/bookings/' in request.path:
                action = 'booking_action'
            elif '/admin/' in request.path:
                action = 'admin_action'
                risk_level = 'high'
            else:
                action = 'data_modification'
        
        # Log failed requests
        if response.status_code >= 400:
            should_log = True
            action = action or 'request_failed'
            if response.status_code == 401:
                action = 'unauthorized_access_attempt'
                risk_level = 'medium'
            elif response.status_code >= 500:
                risk_level = 'high'
        
        # Log slow requests (over 5 seconds)
        if duration > 5.0:
            should_log = True
            action = action or 'slow_request'
            risk_level = 'medium'
        
        if should_log and action:
            user_id = getattr(request.user, 'id', None) if hasattr(request, 'user') else None
            
            AuthAuditLog.log_event(
                action=action,
                success=response.status_code < 400,
                user_id=user_id,
                ip_address=SecurityService.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_method=request.method,
                request_path=request.path,
                failure_reason=f"HTTP {response.status_code}" if response.status_code >= 400 else '',
                risk_level=risk_level,
                metadata={
                    'duration_seconds': duration,
                    'response_status': response.status_code,
                    'content_length': len(response.content) if hasattr(response, 'content') else 0
                }
            )
    
    def _monitor_security_patterns(self, request: HttpRequest, response: HttpResponse):
        """
        Monitor for suspicious security patterns and log accordingly.
        """
        ip_address = SecurityService.get_client_ip(request)
        user_id = getattr(request.user, 'id', None) if hasattr(request, 'user') else None
        
        # Monitor for SQL injection attempts
        if self._detect_sql_injection(request):
            AuthAuditLog.log_event(
                action='suspicious_activity',
                success=False,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_method=request.method,
                request_path=request.path,
                failure_reason='Potential SQL injection attempt',
                risk_level='critical',
                metadata={
                    'attack_type': 'sql_injection',
                    'query_params': dict(request.GET),
                    'response_status': response.status_code
                }
            )
        
        # Monitor for XSS attempts
        if self._detect_xss_attempt(request):
            AuthAuditLog.log_event(
                action='suspicious_activity',
                success=False,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_method=request.method,
                request_path=request.path,
                failure_reason='Potential XSS attempt',
                risk_level='high',
                metadata={
                    'attack_type': 'xss',
                    'query_params': dict(request.GET),
                    'response_status': response.status_code
                }
            )
        
        # Monitor for path traversal attempts
        if self._detect_path_traversal(request):
            AuthAuditLog.log_event(
                action='suspicious_activity',
                success=False,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_method=request.method,
                request_path=request.path,
                failure_reason='Potential path traversal attempt',
                risk_level='high',
                metadata={
                    'attack_type': 'path_traversal',
                    'response_status': response.status_code
                }
            )
    
    def _detect_sql_injection(self, request: HttpRequest) -> bool:
        sql_patterns = [
            'union select', 'drop table', 'insert into', 'delete from',
            '1=1', "' or '1'='1", '" or "1"="1"', '--', '/*', '*/',
            'exec(', 'sp_', 'xp_'
        ]
        # Check query parameters
        query_string = request.META.get('QUERY_STRING', '').lower()
        for pattern in sql_patterns:
            if pattern in query_string:
                return True
        # SKIP request.body check here to avoid RawPostDataException in process_response
        return False
    
    def _detect_xss_attempt(self, request: HttpRequest) -> bool:
        """Detect potential XSS attempts."""
        xss_patterns = [
            '<script', '</script>', 'javascript:', 'onload=', 'onerror=',
            'alert(', 'confirm(', 'prompt(', 'document.cookie'
        ]
        
        # Check query parameters
        query_string = request.META.get('QUERY_STRING', '').lower()
        for pattern in xss_patterns:
            if pattern in query_string:
                return True
        
        return False
    
    def _detect_path_traversal(self, request: HttpRequest) -> bool:
        """Detect potential path traversal attempts."""
        path_patterns = ['../', '..\\', '%2e%2e%2f', '%2e%2e%5c']
        
        path = request.path.lower()
        for pattern in path_patterns:
            if pattern in path:
                return True
        
        return False


class SubscriptionValidationMiddleware(MiddlewareMixin):
    """
    Middleware to validate subscription status and enforce feature limits.
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.user_service = UserProfileService()
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Validate subscription status for protected endpoints.
        """
        # Skip for non-authenticated users
        if not hasattr(request, 'user') or not request.user:
            return None
        
        # Skip for certain paths
        if self._should_skip_validation(request.path):
            return None
        
        # Get user profile
        user_profile = getattr(request, 'user_profile', None)
        if not user_profile:
            return None
        
        # Check if subscription is active
        if not user_profile.is_subscription_active:
            logger.warning(f"Inactive subscription access attempt by user {request.user.id}")
            
            # Log subscription violation
            AuthAuditLog.log_event(
                action='unauthorized_access_attempt',
                success=False,
                user_id=request.user.id,
                ip_address=SecurityService.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_method=request.method,
                request_path=request.path,
                failure_reason='Inactive subscription',
                risk_level='medium',
                metadata={
                    'subscription_status': user_profile.subscription_status,
                    'trial_expired': not user_profile.is_trial_active
                }
            )
            
            return JsonResponse({
                'error': 'Subscription required',
                'message': 'Your trial has expired or subscription is inactive',
                'subscription_status': user_profile.subscription_status,
                'trial_days_remaining': user_profile.trial_days_remaining
            }, status=402)  # Payment Required
        
        # Check feature limits for booking creation
        if self._is_booking_creation(request) and not user_profile.can_create_bookings:
            logger.warning(f"Booking limit exceeded by user {request.user.id}")
            
            return JsonResponse({
                'error': 'Booking limit exceeded',
                'message': f'You have reached your monthly limit of {user_profile.monthly_bookings_limit} bookings',
                'usage': {
                    'used': user_profile.monthly_bookings_used,
                    'limit': user_profile.monthly_bookings_limit,
                    'remaining': user_profile.bookings_remaining
                }
            }, status=402)  # Payment Required
        
        return None
    
    def _should_skip_validation(self, path: str) -> bool:
        """Determine if subscription validation should be skipped."""
        skip_paths = [
            '/api/v1/users/profile/',
            '/api/v1/users/subscription/',
            '/api/v1/auth/',
            '/public/',
            '/health/',
        ]
        
        for skip_path in skip_paths:
            if path.startswith(skip_path):
                return True
        
        return False
    
    def _is_booking_creation(self, request: HttpRequest) -> bool:
        """Check if request is for creating a new booking."""
        return (
            request.method == 'POST' and 
            '/api/v1/bookings/' in request.path
        ) 