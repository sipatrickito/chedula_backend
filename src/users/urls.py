"""
URL Configuration for User Management

This module defines all URL patterns for user authentication, profile management,
subscription handling, and security features.
"""

from django.urls import path
from . import views

app_name = 'users'

urlpatterns = [
    # Health check
    path('health/', views.health_check, name='health_check'),
    
    # User Profile Management
    path('profile/', views.UserProfileView.as_view(), name='user_profile'),
    path('profile/onboarding/', views.UserOnboardingView.as_view(), name='user_onboarding'),
    path('profile/stats/', views.user_stats, name='user_stats'),
    
    # Subscription and Trial Management
    path('subscription/', views.SubscriptionStatusView.as_view(), name='subscription_status'),
    path('subscription/usage/', views.UsageStatsView.as_view(), name='usage_stats'),
    path('subscription/trial/extend/', views.TrialExtensionView.as_view(), name='trial_extension'),
    
    # Security and Session Management
    path('security/report/', views.SecurityReportView.as_view(), name='security_report'),
    path('sessions/', views.UserSessionsView.as_view(), name='user_sessions'),
    
    # Configuration and Choices
    path('business-types/', views.BusinessTypeChoicesView.as_view(), name='business_types'),
    
    # Authentication endpoints (these will handle Supabase auth integration)
    path('auth/verify/', views.VerifyTokenView.as_view(), name='verify_token'),
    path('auth/refresh/', views.RefreshTokenView.as_view(), name='refresh_token'),
    path('auth/logout/', views.LogoutView.as_view(), name='logout'),
] 