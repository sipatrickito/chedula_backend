"""
User Management Views for AI-Powered Appointment Scheduling System

This module provides API views for user profile management, subscription handling,
security monitoring, and trial management.
"""

import logging
from typing import Dict, Any, Optional
from django.utils import timezone
from django.db.models import Count, Q
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes

from .models import UserProfile, AuthAuditLog, UserSession
from .serializers import (
    UserProfileSerializer, UserProfileUpdateSerializer, SubscriptionStatusSerializer,
    UsageStatsSerializer, AuthAuditLogSerializer, UserSessionSerializer,
    BusinessTypeChoicesSerializer, UserOnboardingSerializer, TrialExtensionSerializer,
    SecurityReportSerializer, UserStatsSerializer, ErrorResponseSerializer,
    SuccessResponseSerializer
)
from .services import UserProfileService, SecurityService, SessionService
from .authentication import require_authenticated_user, get_current_user, SupabaseJWTAuthentication

logger = logging.getLogger(__name__)


class UserProfileView(APIView):
    """
    View for user profile management.
    Handles profile retrieval and updates.
    """
    permission_classes = [IsAuthenticated]
    
    @extend_schema(
        summary="Get user profile",
        description="Retrieve the authenticated user's profile information",
        responses={
            200: UserProfileSerializer,
            401: ErrorResponseSerializer,
            404: ErrorResponseSerializer,
        }
    )
    def get(self, request):
        """Get user profile information."""
        try:
            user = require_authenticated_user(request)
            user_service = UserProfileService()
            
            profile = user_service.get_profile(user.id)
            if not profile:
                return Response({
                    'error': 'Profile not found',
                    'message': 'User profile does not exist',
                    'timestamp': timezone.now()
                }, status=status.HTTP_404_NOT_FOUND)
            
            serializer = UserProfileSerializer(profile)
            return Response(serializer.data)
            
        except Exception as e:
            logger.error(f"Error retrieving profile for user {user.id}: {e}")
            return Response({
                'error': 'Profile retrieval failed',
                'message': 'Failed to retrieve user profile',
                'timestamp': timezone.now()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @extend_schema(
        summary="Update user profile",
        description="Update the authenticated user's profile information",
        request=UserProfileUpdateSerializer,
        responses={
            200: UserProfileSerializer,
            400: ErrorResponseSerializer,
            401: ErrorResponseSerializer,
        }
    )
    def put(self, request):
        """Update user profile information."""
        try:
            user = require_authenticated_user(request)
            user_service = UserProfileService()
            
            # Validate the update data
            serializer = UserProfileUpdateSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    'error': 'Validation failed',
                    'message': 'Invalid profile data provided',
                    'details': serializer.errors,
                    'timestamp': timezone.now()
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Update the profile
            profile = user_service.update_profile(
                user_id=user.id,
                profile_data=serializer.validated_data,
                ip_address=SecurityService.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Return updated profile
            response_serializer = UserProfileSerializer(profile)
            return Response(response_serializer.data)
            
        except Exception as e:
            logger.error(f"Error updating profile for user {user.id}: {e}")
            return Response({
                'error': 'Profile update failed',
                'message': str(e),
                'timestamp': timezone.now()
            }, status=status.HTTP_400_BAD_REQUEST)


class SubscriptionStatusView(APIView):
    """
    View for subscription status and trial information.
    """
    permission_classes = [IsAuthenticated]
    
    @extend_schema(
        summary="Get subscription status",
        description="Retrieve subscription and trial status for the authenticated user",
        responses={
            200: SubscriptionStatusSerializer,
            401: ErrorResponseSerializer,
            404: ErrorResponseSerializer,
        }
    )
    def get(self, request):
        """Get subscription status and trial information."""
        try:
            user = require_authenticated_user(request)
            user_service = UserProfileService()
            
            profile = user_service.get_profile(user.id)
            if not profile:
                return Response({
                    'error': 'Profile not found',
                    'message': 'User profile does not exist',
                    'timestamp': timezone.now()
                }, status=status.HTTP_404_NOT_FOUND)
            
            serializer = SubscriptionStatusSerializer(profile)
            return Response(serializer.data)
            
        except Exception as e:
            logger.error(f"Error retrieving subscription status for user {user.id}: {e}")
            return Response({
                'error': 'Subscription status retrieval failed',
                'message': 'Failed to retrieve subscription status',
                'timestamp': timezone.now()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UsageStatsView(APIView):
    """
    View for usage statistics and limits.
    """
    permission_classes = [IsAuthenticated]
    
    @extend_schema(
        summary="Get usage statistics",
        description="Retrieve usage statistics and limits for the authenticated user",
        responses={
            200: UsageStatsSerializer,
            401: ErrorResponseSerializer,
            404: ErrorResponseSerializer,
        }
    )
    def get(self, request):
        """Get usage statistics and limits."""
        try:
            user = require_authenticated_user(request)
            user_service = UserProfileService()
            
            usage_stats = user_service.get_usage_stats(user.id)
            if not usage_stats:
                return Response({
                    'error': 'Profile not found',
                    'message': 'User profile does not exist',
                    'timestamp': timezone.now()
                }, status=status.HTTP_404_NOT_FOUND)
            
            return Response(usage_stats)
            
        except Exception as e:
            logger.error(f"Error retrieving usage stats for user {user.id}: {e}")
            return Response({
                'error': 'Usage stats retrieval failed',
                'message': 'Failed to retrieve usage statistics',
                'timestamp': timezone.now()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserOnboardingView(APIView):
    """
    View for user onboarding process.
    """
    permission_classes = [IsAuthenticated]
    
    @extend_schema(
        summary="Complete user onboarding",
        description="Complete the user onboarding process with business information",
        request=UserOnboardingSerializer,
        responses={
            200: UserProfileSerializer,
            400: ErrorResponseSerializer,
            401: ErrorResponseSerializer,
        }
    )
    def post(self, request):
        """Complete user onboarding."""
        try:
            user = require_authenticated_user(request)
            user_service = UserProfileService()
            
            # Validate onboarding data
            serializer = UserOnboardingSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    'error': 'Validation failed',
                    'message': 'Invalid onboarding data provided',
                    'details': serializer.errors,
                    'timestamp': timezone.now()
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Update profile with onboarding data
            onboarding_data = serializer.validated_data.copy()
            onboarding_data['is_onboarded'] = True
            
            profile = user_service.update_profile(
                user_id=user.id,
                profile_data=onboarding_data,
                ip_address=SecurityService.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Log onboarding completion
            SecurityService.log_authentication_event(
                action='profile_update',
                success=True,
                user_id=user.id,
                request=request,
                metadata={'onboarding_completed': True}
            )
            
            response_serializer = UserProfileSerializer(profile)
            return Response(response_serializer.data)
            
        except Exception as e:
            logger.error(f"Error during onboarding for user {user.id}: {e}")
            return Response({
                'error': 'Onboarding failed',
                'message': str(e),
                'timestamp': timezone.now()
            }, status=status.HTTP_400_BAD_REQUEST)


class BusinessTypeChoicesView(APIView):
    """
    View for retrieving business type choices.
    """
    
    @extend_schema(
        summary="Get business type choices",
        description="Retrieve available business type options",
        responses={200: BusinessTypeChoicesSerializer(many=True)}
    )
    def get(self, request):
        """Get available business type choices."""
        choices = [
            {'value': choice[0], 'label': choice[1]}
            for choice in UserProfile.BUSINESS_TYPES
        ]
        return Response(choices)


class SecurityReportView(APIView):
    """
    View for security reports and audit logs.
    """
    permission_classes = [IsAuthenticated]
    
    @extend_schema(
        summary="Get security report",
        description="Retrieve security report and recent audit events for the authenticated user",
        parameters=[
            OpenApiParameter(
                name='days',
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                description='Number of days to include in report (default: 30)',
                default=30
            )
        ],
        responses={
            200: SecurityReportSerializer,
            401: ErrorResponseSerializer,
        }
    )
    def get(self, request):
        """Get security report for user."""
        try:
            user = require_authenticated_user(request)
            days = int(request.query_params.get('days', 30))
            
            # Get security statistics
            since_date = timezone.now() - timezone.timedelta(days=days)
            
            # Count various event types
            events = AuthAuditLog.objects.filter(
                user_id=user.id,
                timestamp__gte=since_date
            )
            
            total_logins = events.filter(action='login_success').count()
            failed_attempts = events.filter(action='login_failed').count()
            unique_ips = events.values('ip_address').distinct().count()
            suspicious_activities = events.filter(
                risk_level__in=['high', 'critical']
            ).count()
            
            # Get last login
            last_login_event = events.filter(
                action='login_success'
            ).order_by('-timestamp').first()
            
            last_login = last_login_event.timestamp if last_login_event else None
            
            # Get active sessions count
            active_sessions = SessionService.get_active_sessions(user.id).count()
            
            # Get recent events (last 20)
            recent_events = events.order_by('-timestamp')[:20]
            
            report_data = {
                'total_logins': total_logins,
                'failed_attempts': failed_attempts,
                'unique_ips': unique_ips,
                'suspicious_activities': suspicious_activities,
                'last_login': last_login,
                'active_sessions': active_sessions,
                'recent_events': AuthAuditLogSerializer(recent_events, many=True).data
            }
            
            return Response(report_data)
            
        except Exception as e:
            logger.error(f"Error generating security report for user {user.id}: {e}")
            return Response({
                'error': 'Security report generation failed',
                'message': 'Failed to generate security report',
                'timestamp': timezone.now()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserSessionsView(APIView):
    """
    View for managing user sessions.
    """
    permission_classes = [IsAuthenticated]
    
    @extend_schema(
        summary="Get active sessions",
        description="Retrieve all active sessions for the authenticated user",
        responses={
            200: UserSessionSerializer(many=True),
            401: ErrorResponseSerializer,
        }
    )
    def get(self, request):
        """Get all active sessions for user."""
        try:
            user = require_authenticated_user(request)
            sessions = SessionService.get_active_sessions(user.id)
            serializer = UserSessionSerializer(sessions, many=True)
            return Response(serializer.data)
            
        except Exception as e:
            logger.error(f"Error retrieving sessions for user {user.id}: {e}")
            return Response({
                'error': 'Session retrieval failed',
                'message': 'Failed to retrieve user sessions',
                'timestamp': timezone.now()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @extend_schema(
        summary="Deactivate session",
        description="Deactivate a specific user session",
        request={
            'type': 'object',
            'properties': {
                'session_token': {'type': 'string', 'description': 'Session token to deactivate'}
            },
            'required': ['session_token']
        },
        responses={
            200: SuccessResponseSerializer,
            400: ErrorResponseSerializer,
            401: ErrorResponseSerializer,
        }
    )
    def delete(self, request):
        """Deactivate a specific session."""
        try:
            user = require_authenticated_user(request)
            session_token = request.data.get('session_token')
            
            if not session_token:
                return Response({
                    'error': 'Missing session token',
                    'message': 'Session token is required',
                    'timestamp': timezone.now()
                }, status=status.HTTP_400_BAD_REQUEST)
            
            success = SessionService.deactivate_session(session_token)
            
            if success:
                # Log session deactivation
                SecurityService.log_authentication_event(
                    action='logout',
                    success=True,
                    user_id=user.id,
                    request=request,
                    metadata={'session_token': session_token[:8] + '...'}
                )
                
                return Response({
                    'success': True,
                    'message': 'Session deactivated successfully'
                })
            else:
                return Response({
                    'error': 'Session not found',
                    'message': 'Session token not found or already inactive',
                    'timestamp': timezone.now()
                }, status=status.HTTP_404_NOT_FOUND)
                
        except Exception as e:
            logger.error(f"Error deactivating session for user {user.id}: {e}")
            return Response({
                'error': 'Session deactivation failed',
                'message': 'Failed to deactivate session',
                'timestamp': timezone.now()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Admin-only views for trial and subscription management

class TrialExtensionView(APIView):
    """
    Admin view for extending user trials.
    """
    permission_classes = [IsAuthenticated]
    
    @extend_schema(
        summary="Extend user trial (Admin only)",
        description="Extend trial period for a specific user",
        request=TrialExtensionSerializer,
        responses={
            200: SuccessResponseSerializer,
            400: ErrorResponseSerializer,
            401: ErrorResponseSerializer,
            403: ErrorResponseSerializer,
        }
    )
    def post(self, request):
        """Extend trial for a user (admin only)."""
        try:
            admin_user = require_authenticated_user(request)
            
            # TODO: Add admin permission check when role system is implemented
            # For now, we'll allow any authenticated user (for development)
            
            # Validate request data
            serializer = TrialExtensionSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    'error': 'Validation failed',
                    'message': 'Invalid extension data provided',
                    'details': serializer.errors,
                    'timestamp': timezone.now()
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Extend trial
            user_service = UserProfileService()
            success = user_service.extend_trial(
                user_id=str(serializer.validated_data['user_id']),
                days=serializer.validated_data['days'],
                reason=serializer.validated_data['reason'],
                admin_user_id=admin_user.id
            )
            
            if success:
                return Response({
                    'success': True,
                    'message': f"Trial extended by {serializer.validated_data['days']} days"
                })
            else:
                return Response({
                    'error': 'Extension failed',
                    'message': 'Failed to extend trial (maximum extensions reached or user not found)',
                    'timestamp': timezone.now()
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Error extending trial: {e}")
            return Response({
                'error': 'Trial extension failed',
                'message': str(e),
                'timestamp': timezone.now()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([])
def health_check(request):
    """
    Health check endpoint for monitoring.
    """
    return Response({
        'status': 'healthy',
        'timestamp': timezone.now(),
        'service': 'user-management'
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_stats(request):
    """
    Get comprehensive user statistics.
    """
    try:
        user = require_authenticated_user(request)
        user_service = UserProfileService()
        
        profile = user_service.get_profile(user.id)
        if not profile:
            return Response({
                'error': 'Profile not found',
                'message': 'User profile does not exist',
                'timestamp': timezone.now()
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Compile comprehensive stats
        stats = {
            'profile': UserProfileSerializer(profile).data,
            'subscription': SubscriptionStatusSerializer(profile).data,
            'usage': user_service.get_usage_stats(user.id),
        }
        
        return Response(stats)
        
    except Exception as e:
        logger.error(f"Error retrieving user stats for {user.id}: {e}")
        return Response({
            'error': 'Stats retrieval failed',
            'message': 'Failed to retrieve user statistics',
            'timestamp': timezone.now()
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyTokenView(APIView):
    """
    View for verifying Supabase JWT tokens.
    This is useful for frontend to check if a token is still valid.
    """
    permission_classes = []  # No permission required since we're verifying the token
    
    @extend_schema(
        summary="Verify JWT token",
        description="Verify if a Supabase JWT token is valid and return user information",
        request={
            'type': 'object',
            'properties': {
                'token': {'type': 'string', 'description': 'JWT token to verify'}
            },
            'required': ['token']
        },
        responses={
            200: UserProfileSerializer,
            401: ErrorResponseSerializer,
        }
    )
    def post(self, request):
        """Verify JWT token and return user information."""
        try:
            token = request.data.get('token')
            if not token:
                return Response({
                    'error': 'Token required',
                    'message': 'JWT token is required for verification',
                    'timestamp': timezone.now()
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Use our authentication backend to verify the token
            auth_backend = SupabaseJWTAuthentication()
            
            try:
                user, validated_token = auth_backend.authenticate_credentials(token)
                
                # Get user profile
                user_service = UserProfileService()
                profile = user_service.get_profile(user.id)
                
                if profile:
                    serializer = UserProfileSerializer(profile)
                    return Response({
                        'valid': True,
                        'user': serializer.data,
                        'token_info': {
                            'user_id': user.id,
                            'email': user.email,
                            'exp': user.exp,
                            'iat': user.iat
                        }
                    })
                else:
                    # Create profile if it doesn't exist
                    profile = user_service.get_or_create_profile(
                        user_id=user.id,
                        email=user.email,
                        user_metadata=user.user_metadata
                    )
                    serializer = UserProfileSerializer(profile)
                    return Response({
                        'valid': True,
                        'user': serializer.data,
                        'token_info': {
                            'user_id': user.id,
                            'email': user.email,
                            'exp': user.exp,
                            'iat': user.iat
                        }
                    })
                
            except Exception as e:
                return Response({
                    'valid': False,
                    'error': 'Invalid token',
                    'message': str(e),
                    'timestamp': timezone.now()
                }, status=status.HTTP_401_UNAUTHORIZED)
                
        except Exception as e:
            logger.error(f"Error verifying token: {e}")
            return Response({
                'error': 'Token verification failed',
                'message': 'Failed to verify token',
                'timestamp': timezone.now()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RefreshTokenView(APIView):
    """
    View for refreshing JWT tokens.
    Note: Actual token refresh is handled by Supabase on the frontend,
    but this endpoint can be used for logging and session management.
    """
    permission_classes = [IsAuthenticated]
    
    @extend_schema(
        summary="Refresh session",
        description="Log token refresh and update session information",
        responses={
            200: SuccessResponseSerializer,
            401: ErrorResponseSerializer,
        }
    )
    def post(self, request):
        """Handle token refresh logging."""
        try:
            user = require_authenticated_user(request)
            
            # Log token refresh event
            SecurityService.log_authentication_event(
                action='token_refresh',
                success=True,
                user_id=user.id,
                request=request
            )
            
            # Update user's last login
            user_service = UserProfileService()
            profile = user_service.get_profile(user.id)
            if profile:
                profile.update_last_login()
            
            return Response({
                'success': True,
                'message': 'Token refresh logged successfully'
            })
            
        except Exception as e:
            logger.error(f"Error handling token refresh: {e}")
            return Response({
                'error': 'Token refresh failed',
                'message': 'Failed to process token refresh',
                'timestamp': timezone.now()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(APIView):
    """
    View for handling user logout.
    Deactivates sessions and logs logout event.
    """
    permission_classes = [IsAuthenticated]
    
    @extend_schema(
        summary="User logout",
        description="Log out user and deactivate sessions",
        request={
            'type': 'object',
            'properties': {
                'session_token': {'type': 'string', 'description': 'Session token to deactivate (optional)'}
            }
        },
        responses={
            200: SuccessResponseSerializer,
            401: ErrorResponseSerializer,
        }
    )
    def post(self, request):
        """Handle user logout."""
        try:
            user = require_authenticated_user(request)
            session_token = request.data.get('session_token')
            
            # Deactivate specific session if provided
            if session_token:
                SessionService.deactivate_session(session_token)
            
            # Log logout event
            SecurityService.log_authentication_event(
                action='logout',
                success=True,
                user_id=user.id,
                request=request,
                metadata={'session_token': session_token[:8] + '...' if session_token else None}
            )
            
            return Response({
                'success': True,
                'message': 'Logout successful'
            })
            
        except Exception as e:
            logger.error(f"Error handling logout: {e}")
            return Response({
                'error': 'Logout failed',
                'message': 'Failed to process logout',
                'timestamp': timezone.now()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
