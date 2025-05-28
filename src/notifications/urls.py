from django.urls import path
from .views import SendNotificationEmailView

urlpatterns = [
    path('send/', SendNotificationEmailView.as_view(), name='send-notification-email'),
] 