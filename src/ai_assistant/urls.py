from django.urls import path
from .views import OpenRouterChatView

urlpatterns = [
    path('chat/', OpenRouterChatView.as_view(), name='openrouter-chat'),
] 