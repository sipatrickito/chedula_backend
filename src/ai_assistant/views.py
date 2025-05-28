from django.shortcuts import render
import os
import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated  # Optional: require auth

# views for ai_assistant app

class OpenRouterChatView(APIView):
    permission_classes = [IsAuthenticated]  # Remove if you want it public

    def post(self, request):
        prompt = request.data.get("prompt")
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not prompt or not api_key:
            return Response({"error": "Missing prompt or API key"}, status=400)

        # Call OpenRouter API
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"messages": [{"role": "user", "content": prompt}]}
        )
        return Response(response.json(), status=response.status_code)
