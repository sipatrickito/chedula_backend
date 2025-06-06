"""
WebSocket routing configuration for AI Assistant chat functionality.

This module defines the URL patterns for WebSocket connections,
specifically for real-time chat communication with the AI assistant.
"""

from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/chat/$', consumers.ChatConsumer.as_asgi()),
    re_path(r'ws/chat/(?P<session_id>[0-9a-f-]+)/$', consumers.ChatConsumer.as_asgi()),
] 