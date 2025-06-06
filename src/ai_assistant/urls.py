from django.urls import path
from . import views

app_name = 'ai_assistant'

urlpatterns = [
    # Chat endpoints
    path('chat/history/', views.ChatHistoryView.as_view(), name='chat_history'),
    path('chat/test/', views.ChatTestView.as_view(), name='chat_test'),
    
    # AI processing endpoints
    path('process/', views.ProcessMessageView.as_view(), name='process_message'),
    path('capabilities/', views.CapabilitiesView.as_view(), name='capabilities'),
    
    # Action endpoints
    path('actions/', views.ActionHistoryView.as_view(), name='action_history'),
    path('actions/<uuid:action_id>/', views.ActionDetailView.as_view(), name='action_detail'),
] 