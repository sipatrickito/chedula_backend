from django.shortcuts import render
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated  # Optional

# views for notifications app

class SendNotificationEmailView(APIView):
    permission_classes = [IsAuthenticated]  # Remove if you want it public

    def post(self, request):
        subject = request.data.get("subject")
        message = request.data.get("message")
        to_email = request.data.get("to_email")

        if not subject or not message or not to_email:
            return Response({"error": "Missing fields"}, status=400)

        send_mail(
            subject,
            message,
            None,  # Uses DEFAULT_FROM_EMAIL from settings.py
            [to_email],
            fail_silently=False,
        )
        return Response({"status": "Email sent"})
