"""
URL Configuration for AI Assistant API endpoints.

Simple HTTP-based chat functionality 
"""

from django.urls import path
from . import views

app_name = 'ai_assistant'

urlpatterns = [
    # Chat endpoints
    path('chat/send/', views.send_message, name='send_message'),
    path('chat/history/', views.chat_history, name='chat_history'),
    path('chat/session/', views.create_session, name='create_session'),
    
    # Utility endpoints
    path('test/', views.test_connection, name='test_connection'),
    path('capabilities/', views.capabilities, name='capabilities'),
    
    # Action endpoints (class-based views)
    path('actions/', views.ActionHistoryView.as_view(), name='action_history'),
    path('actions/<uuid:action_id>/', views.ActionDetailView.as_view(), name='action_detail'),
] 