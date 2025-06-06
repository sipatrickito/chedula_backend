"""
Supabase Authentication Backend for Django REST Framework

This module provides custom authentication classes that integrate Supabase Auth
with Django REST Framework, handling JWT token validation and user identification.
"""

import jwt
import logging
from typing import Optional, Tuple, Dict, Any
from django.contrib.auth.models import AnonymousUser
from django.conf import settings
from rest_framework import authentication, exceptions
from rest_framework.request import Request
from supabase import create_client, Client
from .models import UserProfile
from .services import UserProfileService

logger = logging.getLogger(__name__)


class SupabaseUser:
    """
    Custom user class for Supabase authentication that provides compatibility
    with Django's authentication system without using Django's User model.
    """
    
    def __init__(self, user_data: Dict[str, Any]):
        self.id = user_data.get('sub')  # Supabase user ID
        self.email = user_data.get('email')
        self.is_authenticated = True
        self.is_anonymous = False
        self.is_active = True
        self.user_metadata = user_data.get('user_metadata', {})
        self.app_metadata = user_data.get('app_metadata', {})
        self.aud = user_data.get('aud')
        self.role = user_data.get('role', 'authenticated')
        self.iat = user_data.get('iat')
        self.exp = user_data.get('exp')
        
        # Additional user information
        self.phone = user_data.get('phone')
        self.email_confirmed_at = user_data.get('email_confirmed_at')
        self.phone_confirmed_at = user_data.get('phone_confirmed_at')
        self.confirmed_at = user_data.get('confirmed_at')
        
    def __str__(self):
        return f"SupabaseUser(id={self.id}, email={self.email})"
    
    def is_authenticated(self):
        return True
    
    def has_perm(self, perm, obj=None):
        """Simple permission check - can be enhanced with role-based permissions"""
        return True
    
    def has_module_perms(self, app_label):
        """Simple module permission check"""
        return True


class SupabaseJWTAuthentication(authentication.BaseAuthentication):
    """
    Custom authentication class that validates Supabase JWT tokens and creates
    SupabaseUser instances for use in Django REST Framework views.
    """
    
    def __init__(self):
        self.supabase_client: Optional[Client] = None
        self.jwt_secret = settings.SUPABASE_JWT_SECRET
        self.user_service = UserProfileService()
        
        if settings.SUPABASE_URL and settings.SUPABASE_SERVICE_ROLE_KEY:
            try:
                self.supabase_client = create_client(
                    settings.SUPABASE_URL,
                    settings.SUPABASE_SERVICE_ROLE_KEY
                )
            except Exception as e:
                logger.error(f"Failed to initialize Supabase client: {e}")
    
    def authenticate(self, request: Request) -> Optional[Tuple[SupabaseUser, str]]:
        """
        Authenticate the request and return a two-tuple of (user, token).
        """
        # Get the authorization header
        auth_header = authentication.get_authorization_header(request).split()
        
        if not auth_header or auth_header[0].lower() != b'bearer':
            return None
        
        if len(auth_header) == 1:
            msg = 'Invalid token header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth_header) > 2:
            msg = 'Invalid token header. Token string should not contain spaces.'
            raise exceptions.AuthenticationFailed(msg)
        
        try:
            token = auth_header[1].decode('utf-8')
        except UnicodeError:
            msg = 'Invalid token header. Token string should not contain invalid characters.'
            raise exceptions.AuthenticationFailed(msg)
        
        return self.authenticate_credentials(token)
    
    def authenticate_credentials(self, token: str) -> Tuple[SupabaseUser, str]:
        """
        Validate the JWT token and return the user and token.
        """
        if not self.jwt_secret:
            raise exceptions.AuthenticationFailed('Supabase JWT secret not configured.')
        
        try:
            # Decode and validate the JWT token
            # Add clock skew tolerance to handle timing differences
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=['HS256'],
                audience='authenticated',
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_aud': True,
                    'require_exp': True,
                    'require_iat': True,
                    'require_sub': True
                },
                # Allow 60 seconds of clock skew tolerance
                leeway=60
            )
            
            # Log authentication attempt
            logger.info(f"Successful JWT validation for user: {payload.get('sub')}")
            
            # Create SupabaseUser instance
            user = SupabaseUser(payload)
            
            # Ensure user profile exists in Django database
            self._ensure_user_profile(user)
            
            return (user, token)
            
        except jwt.ExpiredSignatureError:
            logger.warning(f"Expired JWT token attempted: {token[:20]}...")
            raise exceptions.AuthenticationFailed('Token has expired.')
        
        except jwt.InvalidAudienceError:
            logger.warning(f"Invalid audience in JWT token: {token[:20]}...")
            raise exceptions.AuthenticationFailed('Invalid token audience.')
        
        except jwt.InvalidSignatureError:
            logger.warning(f"Invalid signature in JWT token: {token[:20]}...")
            raise exceptions.AuthenticationFailed('Invalid token signature.')
        
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {token[:20]}... Error: {e}")
            raise exceptions.AuthenticationFailed('Invalid token.')
        
        except Exception as e:
            logger.error(f"Unexpected error during token validation: {e}")
            raise exceptions.AuthenticationFailed('Authentication failed.')
    
    def _ensure_user_profile(self, user: SupabaseUser) -> None:
        """
        Ensure that a UserProfile exists for the authenticated Supabase user.
        Creates a profile if one doesn't exist.
        """
        try:
            profile = self.user_service.get_or_create_profile(
                user_id=user.id,
                email=user.email,
                user_metadata=user.user_metadata
            )
            
            # Attach profile to user for easy access in views
            user.profile = profile
            
        except Exception as e:
            logger.error(f"Failed to ensure user profile for {user.id}: {e}")
            # Don't fail authentication if profile creation fails
            # The profile can be created later
    
    def authenticate_header(self, request: Request) -> str:
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response.
        """
        return 'Bearer'


class SupabaseServiceAuthentication:
    """
    Service class for Supabase administrative operations that require
    service role access. This is separate from user authentication.
    """
    
    def __init__(self):
        self.client: Optional[Client] = None
        
        if settings.SUPABASE_URL and settings.SUPABASE_SERVICE_ROLE_KEY:
            try:
                self.client = create_client(
                    settings.SUPABASE_URL,
                    settings.SUPABASE_SERVICE_ROLE_KEY
                )
            except Exception as e:
                logger.error(f"Failed to initialize Supabase service client: {e}")
    
    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user data from Supabase by user ID using service role."""
        if not self.client:
            return None
        
        try:
            response = self.client.auth.admin.get_user_by_id(user_id)
            return response.user if response.user else None
        except Exception as e:
            logger.error(f"Failed to get user {user_id} from Supabase: {e}")
            return None
    
    def update_user_metadata(self, user_id: str, metadata: Dict[str, Any]) -> bool:
        """Update user metadata in Supabase."""
        if not self.client:
            return False
        
        try:
            self.client.auth.admin.update_user_by_id(
                user_id,
                {"user_metadata": metadata}
            )
            return True
        except Exception as e:
            logger.error(f"Failed to update user metadata for {user_id}: {e}")
            return False
    
    def delete_user(self, user_id: str) -> bool:
        """Delete user from Supabase (admin operation)."""
        if not self.client:
            return False
        
        try:
            self.client.auth.admin.delete_user(user_id)
            return True
        except Exception as e:
            logger.error(f"Failed to delete user {user_id} from Supabase: {e}")
            return False


def get_current_user(request: Request) -> Optional[SupabaseUser]:
    """
    Utility function to get the current authenticated user from a request.
    Returns None if the user is not authenticated.
    """
    if hasattr(request, 'user') and isinstance(request.user, SupabaseUser):
        return request.user
    return None


def require_authenticated_user(request: Request) -> SupabaseUser:
    """
    Utility function that returns the authenticated user or raises an exception.
    Use this when you need to ensure the user is authenticated.
    """
    user = get_current_user(request)
    if not user:
        raise exceptions.NotAuthenticated('Authentication required.')
    return user 