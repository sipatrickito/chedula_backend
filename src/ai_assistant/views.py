from django.shortcuts import render
import os
import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated  # Optional: require auth
from rest_framework import status, permissions
from django.shortcuts import get_object_or_404
from django.core.paginator import Paginator
from users.authentication import SupabaseJWTAuthentication, require_authenticated_user
from .models import ChatMessage, ChatSession, AIAction
from .services import AIAssistantService
import logging

logger = logging.getLogger(__name__)

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


class ChatHistoryView(APIView):
    """Retrieve chat history for the authenticated user"""
    authentication_classes = [SupabaseJWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            user = require_authenticated_user(request)
            
            # Get query parameters
            limit = int(request.query_params.get('limit', 50))
            offset = int(request.query_params.get('offset', 0))
            session_id = request.query_params.get('session_id')
            
            # Base query
            messages = ChatMessage.objects.filter(user_id=user.id)
            
            # Filter by session if provided
            if session_id:
                messages = messages.filter(session_id=session_id)
            
            # Order by timestamp (newest first)
            messages = messages.order_by('-timestamp')
            
            # Apply pagination
            messages = messages[offset:offset + limit]
            
            # Serialize messages
            messages_data = []
            for message in messages:
                messages_data.append({
                    'id': message.id,
                    'session_id': str(message.session_id) if message.session_id else None,
                    'sender_type': message.sender_type,
                    'content': message.content,
                    'metadata': message.metadata,
                    'timestamp': message.timestamp.isoformat()
                })
            
            return Response({
                'messages': messages_data,
                'count': len(messages_data),
                'has_more': len(messages_data) == limit
            })
            
        except Exception as e:
            logger.error(f"Error retrieving chat history for user {user.id}: {e}")
            return Response(
                {'error': 'Failed to retrieve chat history'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ChatTestView(APIView):
    """Test endpoint for chat functionality"""
    authentication_classes = [SupabaseJWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            user = require_authenticated_user(request)
            message = request.data.get('message', '')
            
            if not message:
                return Response(
                    {'error': 'Message is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Save user message
            user_message = ChatMessage.objects.create(
                user_id=user.id,
                sender_type='user',
                content=message
            )
            
            # Create a simple AI response for testing
            ai_response = f"Test response: I received your message '{message}'"
            
            ai_message = ChatMessage.objects.create(
                user_id=user.id,
                sender_type='ai',
                content=ai_response,
                metadata={'test_mode': True}
            )
            
            return Response({
                'user_message': {
                    'id': user_message.id,
                    'content': user_message.content,
                    'timestamp': user_message.timestamp.isoformat()
                },
                'ai_response': {
                    'id': ai_message.id,
                    'content': ai_message.content,
                    'timestamp': ai_message.timestamp.isoformat()
                }
            })
            
        except Exception as e:
            logger.error(f"Error in chat test for user {user.id}: {e}")
            return Response(
                {'error': 'Chat test failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ProcessMessageView(APIView):
    """Process a message through the AI Assistant"""
    authentication_classes = [SupabaseJWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            user = require_authenticated_user(request)
            message = request.data.get('message', '')
            session_id = request.data.get('session_id')
            
            if not message:
                return Response(
                    {'error': 'Message is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Initialize AI Assistant service
            ai_service = AIAssistantService()
            
            # Process the message
            result = ai_service.process_message(
                user_id=user.id,
                message=message,
                session_id=session_id
            )
            
            return Response(result)
            
        except Exception as e:
            logger.error(f"Error processing message for user {user.id}: {e}")
            return Response(
                {'error': 'Failed to process message'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CapabilitiesView(APIView):
    """Get AI Assistant capabilities"""
    authentication_classes = [SupabaseJWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({
            'capabilities': [
                'booking_management',
                'customer_management',
                'service_management',
                'equipment_management',
                'availability_checking',
                'schedule_optimization'
            ],
            'supported_actions': [
                'create_booking',
                'update_booking',
                'cancel_booking',
                'check_availability',
                'create_customer',
                'update_customer',
                'search_customers',
                'create_service',
                'update_service',
                'get_equipment_status'
            ],
            'example_commands': [
                "Book Camera A for John Smith next Monday",
                "Check availability for this Friday",
                "Add new customer Jane Doe, email jane@email.com",
                "Update Camera B daily rate to $150",
                "Cancel booking #123",
                "Show me John's booking history"
            ]
        })


class ActionHistoryView(APIView):
    """Get AI action history"""
    authentication_classes = [SupabaseJWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            user = require_authenticated_user(request)
            
            # Get query parameters
            limit = int(request.query_params.get('limit', 20))
            offset = int(request.query_params.get('offset', 0))
            action_type = request.query_params.get('action_type')
            status_filter = request.query_params.get('status')
            
            # Base query
            actions = AIAction.objects.filter(user_id=user.id)
            
            # Apply filters
            if action_type:
                actions = actions.filter(action_type=action_type)
            if status_filter:
                actions = actions.filter(status=status_filter)
            
            # Order by execution time (newest first)
            actions = actions.order_by('-executed_at')
            
            # Apply pagination
            actions = actions[offset:offset + limit]
            
            # Serialize actions
            actions_data = []
            for action in actions:
                actions_data.append({
                    'id': str(action.id),
                    'action_type': action.action_type,
                    'target_model': action.target_model,
                    'target_id': str(action.target_id) if action.target_id else None,
                    'parameters': action.parameters,
                    'status': action.status,
                    'error_message': action.error_message,
                    'executed_at': action.executed_at.isoformat()
                })
            
            return Response({
                'actions': actions_data,
                'count': len(actions_data),
                'has_more': len(actions_data) == limit
            })
            
        except Exception as e:
            logger.error(f"Error retrieving action history for user {user.id}: {e}")
            return Response(
                {'error': 'Failed to retrieve action history'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ActionDetailView(APIView):
    """Get details of a specific AI action"""
    authentication_classes = [SupabaseJWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, action_id):
        try:
            user = require_authenticated_user(request)
            
            action = get_object_or_404(
                AIAction,
                id=action_id,
                user_id=user.id
            )
            
            return Response({
                'id': str(action.id),
                'message_id': action.message_id,
                'action_type': action.action_type,
                'target_model': action.target_model,
                'target_id': str(action.target_id) if action.target_id else None,
                'parameters': action.parameters,
                'status': action.status,
                'error_message': action.error_message,
                'executed_at': action.executed_at.isoformat()
            })
            
        except Exception as e:
            logger.error(f"Error retrieving action {action_id} for user {user.id}: {e}")
            return Response(
                {'error': 'Failed to retrieve action details'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
