"""
AI Assistant Models for Chat Functionality and Action Tracking

This module defines the database models for the AI-powered scheduling assistant,
including chat sessions, message storage, action tracking, and context management.
"""

import uuid
import json
from django.db import models
from django.utils import timezone
from typing import Dict, Any, List, Optional


class ChatSession(models.Model):
    """
    Represents a conversation session between user and AI assistant.
    Stores conversation context and session metadata.
    """
    
    SESSION_STATUS = [
        ('active', 'Active'),
        ('paused', 'Paused'),
        ('ended', 'Ended'),
        ('archived', 'Archived'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.UUIDField(db_index=True)  # Links to Supabase auth.users.id
    
    # Session metadata
    title = models.CharField(max_length=255, blank=True)  # Auto-generated or user-defined
    status = models.CharField(max_length=20, choices=SESSION_STATUS, default='active')
    
    # Context management
    context = models.JSONField(default=dict, blank=True)  # Conversation state and context
    last_intent = models.CharField(max_length=100, blank=True)  # Last recognized intent
    active_workflow = models.CharField(max_length=100, blank=True)  # Current workflow state
    
    # Session statistics
    message_count = models.IntegerField(default=0)
    actions_performed = models.IntegerField(default=0)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_activity = models.DateTimeField(auto_now=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'chat_sessions'
        indexes = [
            models.Index(fields=['user_id', 'last_activity']),
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['user_id', 'status']),
        ]
        ordering = ['-last_activity']
    
    def __str__(self):
        return f"Chat Session {self.id} - {self.title or 'Untitled'}"
    
    def end_session(self):
        """Mark session as ended"""
        self.status = 'ended'
        self.ended_at = timezone.now()
        self.save()
    
    def update_context(self, new_context: Dict[str, Any]):
        """Update session context with new information"""
        self.context.update(new_context)
        self.save(update_fields=['context', 'updated_at'])
    
    def increment_message_count(self):
        """Increment message count for this session"""
        self.message_count += 1
        self.save(update_fields=['message_count', 'last_activity'])
    
    def increment_action_count(self):
        """Increment action count for this session"""
        self.actions_performed += 1
        self.save(update_fields=['actions_performed', 'last_activity'])


class ChatMessage(models.Model):
    """
    Stores individual chat messages between user and AI assistant.
    Includes metadata about entities, actions, and processing results.
    """
    
    SENDER_TYPES = [
        ('user', 'User'),
        ('ai', 'AI Assistant'),
        ('system', 'System'),
    ]
    
    MESSAGE_STATUS = [
        ('sent', 'Sent'),
        ('processing', 'Processing'),
        ('processed', 'Processed'),
        ('failed', 'Failed'),
        ('edited', 'Edited'),
        ('deleted', 'Deleted'),
    ]
    
    id = models.BigAutoField(primary_key=True)
    session_id = models.UUIDField(null=True, blank=True, db_index=True)  # Optional session grouping
    user_id = models.UUIDField(db_index=True)  # Links to Supabase auth.users.id
    
    # Message content
    sender_type = models.CharField(max_length=10, choices=SENDER_TYPES)
    content = models.TextField()
    
    # Message metadata
    status = models.CharField(max_length=20, choices=MESSAGE_STATUS, default='sent')
    metadata = models.JSONField(default=dict, blank=True)  # Actions taken, entities, errors
    
    # AI processing information
    ai_model_used = models.CharField(max_length=100, blank=True)
    processing_time_ms = models.IntegerField(null=True, blank=True)
    confidence_score = models.FloatField(null=True, blank=True)
    entities_extracted = models.JSONField(default=list, blank=True)
    intent_recognized = models.CharField(max_length=100, blank=True)
    
    # Response metadata (for AI messages)
    parent_message_id = models.BigIntegerField(null=True, blank=True)  # References user message
    tokens_used = models.IntegerField(null=True, blank=True)
    
    # Timestamps
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    edited_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'chat_messages'
        indexes = [
            models.Index(fields=['user_id', 'timestamp']),
            models.Index(fields=['session_id', 'timestamp']),
            models.Index(fields=['sender_type', 'timestamp']),
            models.Index(fields=['status', 'timestamp']),
            models.Index(fields=['parent_message_id']),
        ]
        ordering = ['timestamp']
    
    def __str__(self):
        content_preview = self.content[:50] + "..." if len(self.content) > 50 else self.content
        return f"{self.sender_type.upper()}: {content_preview}"
    
    def mark_as_processing(self):
        """Mark message as being processed"""
        self.status = 'processing'
        self.save(update_fields=['status'])
    
    def mark_as_processed(self, metadata: Dict[str, Any] = None):
        """Mark message as successfully processed"""
        self.status = 'processed'
        if metadata:
            self.metadata.update(metadata)
        self.save(update_fields=['status', 'metadata'])
    
    def mark_as_failed(self, error_message: str):
        """Mark message as failed with error details"""
        self.status = 'failed'
        self.metadata['error'] = error_message
        self.metadata['failed_at'] = timezone.now().isoformat()
        self.save(update_fields=['status', 'metadata'])
    
    def add_entities(self, entities: List[Dict[str, Any]]):
        """Add extracted entities to the message"""
        self.entities_extracted = entities
        self.save(update_fields=['entities_extracted'])
    
    def set_ai_response_data(self, model: str, processing_time: int, tokens: int, confidence: float = None):
        """Set AI response metadata"""
        self.ai_model_used = model
        self.processing_time_ms = processing_time
        self.tokens_used = tokens
        if confidence is not None:
            self.confidence_score = confidence
        self.save(update_fields=['ai_model_used', 'processing_time_ms', 'tokens_used', 'confidence_score'])


class AIAction(models.Model):
    """
    Tracks actions performed by the AI assistant on behalf of the user.
    Provides audit trail and rollback capabilities for AI-executed operations.
    """
    
    ACTION_TYPES = [
        # Calendar Management Actions
        ('create_booking', 'Create Booking'),
        ('update_booking', 'Update Booking'),
        ('cancel_booking', 'Cancel Booking'),
        ('reschedule_booking', 'Reschedule Booking'),
        ('check_availability', 'Check Availability'),
        
        # Customer Management Actions
        ('create_customer', 'Create Customer'),
        ('update_customer', 'Update Customer'),
        ('search_customer', 'Search Customer'),
        ('get_customer_history', 'Get Customer History'),
        
        # Service/Equipment Management Actions
        ('create_service', 'Create Service'),
        ('update_service', 'Update Service'),
        ('update_pricing', 'Update Pricing'),
        ('check_equipment_availability', 'Check Equipment Availability'),
        ('create_equipment', 'Create Equipment'),
        ('update_equipment', 'Update Equipment'),
        
        # System Actions
        ('send_notification', 'Send Notification'),
        ('generate_report', 'Generate Report'),
        ('export_data', 'Export Data'),
        ('error_occurred', 'Error Occurred'),
    ]
    
    ACTION_STATUS = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
        ('rolled_back', 'Rolled Back'),
    ]
    
    TARGET_MODELS = [
        ('booking', 'Booking'),
        ('customer', 'Customer'),
        ('service', 'Service'),
        ('equipment', 'Equipment'),
        ('notification', 'Notification'),
        ('report', 'Report'),
        ('system', 'System'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    message_id = models.BigIntegerField(db_index=True)  # Links to ChatMessage
    user_id = models.UUIDField(db_index=True)  # Links to Supabase auth.users.id
    session_id = models.UUIDField(null=True, blank=True, db_index=True)  # Optional session link
    
    # Action details
    action_type = models.CharField(max_length=50, choices=ACTION_TYPES)
    target_model = models.CharField(max_length=50, choices=TARGET_MODELS)
    target_id = models.UUIDField(null=True, blank=True)  # ID of created/modified object
    
    # Action parameters and results
    parameters = models.JSONField(default=dict)  # Input parameters for the action
    result = models.JSONField(default=dict, blank=True)  # Result data from the action
    status = models.CharField(max_length=20, choices=ACTION_STATUS, default='pending')
    error_message = models.TextField(blank=True)
    
    # Rollback information
    rollback_data = models.JSONField(default=dict, blank=True)  # Data needed for rollback
    can_rollback = models.BooleanField(default=True)
    rollback_executed_at = models.DateTimeField(null=True, blank=True)
    
    # Validation and confirmation
    requires_confirmation = models.BooleanField(default=False)
    confirmed_by_user = models.BooleanField(default=False)
    confirmation_requested_at = models.DateTimeField(null=True, blank=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'ai_actions'
        indexes = [
            models.Index(fields=['user_id', 'created_at']),
            models.Index(fields=['message_id']),
            models.Index(fields=['session_id', 'created_at']),
            models.Index(fields=['action_type', 'status']),
            models.Index(fields=['target_model', 'target_id']),
            models.Index(fields=['status', 'created_at']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.action_type} - {self.status} ({self.id})"
    
    def mark_in_progress(self):
        """Mark action as in progress"""
        self.status = 'in_progress'
        self.started_at = timezone.now()
        self.save(update_fields=['status', 'started_at'])
    
    def mark_completed(self, result: Dict[str, Any] = None, target_id: str = None):
        """Mark action as completed with optional result data"""
        self.status = 'completed'
        self.completed_at = timezone.now()
        if result:
            self.result = result
        if target_id:
            self.target_id = target_id
        self.save(update_fields=['status', 'completed_at', 'result', 'target_id'])
    
    def mark_failed(self, error_message: str):
        """Mark action as failed with error message"""
        self.status = 'failed'
        self.error_message = error_message
        self.completed_at = timezone.now()
        self.save(update_fields=['status', 'error_message', 'completed_at'])
    
    def request_confirmation(self):
        """Request user confirmation for this action"""
        self.requires_confirmation = True
        self.confirmation_requested_at = timezone.now()
        self.save(update_fields=['requires_confirmation', 'confirmation_requested_at'])
    
    def confirm_action(self):
        """Confirm the action as approved by user"""
        self.confirmed_by_user = True
        self.confirmed_at = timezone.now()
        self.save(update_fields=['confirmed_by_user', 'confirmed_at'])
    
    def execute_rollback(self, rollback_reason: str = ''):
        """Execute rollback of this action"""
        if not self.can_rollback:
            raise ValueError("This action cannot be rolled back")
        
        self.status = 'rolled_back'
        self.rollback_executed_at = timezone.now()
        if rollback_reason:
            self.metadata = self.metadata or {}
            self.metadata['rollback_reason'] = rollback_reason
        self.save(update_fields=['status', 'rollback_executed_at', 'metadata'])
    
    @property
    def duration_seconds(self) -> Optional[int]:
        """Calculate action duration in seconds"""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        return None


class ConversationContext(models.Model):
    """
    Stores structured conversation context for better AI understanding.
    Tracks entities, intents, and workflow state across messages.
    """
    
    CONTEXT_TYPES = [
        ('entity', 'Entity'),
        ('intent', 'Intent'),
        ('workflow', 'Workflow State'),
        ('preference', 'User Preference'),
        ('temporary', 'Temporary Data'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session_id = models.UUIDField(db_index=True)  # Links to ChatSession
    user_id = models.UUIDField(db_index=True)  # Links to Supabase auth.users.id
    
    # Context details
    context_type = models.CharField(max_length=20, choices=CONTEXT_TYPES)
    key = models.CharField(max_length=100)  # Context key/name
    value = models.JSONField()  # Context value (can be any JSON-serializable data)
    
    # Metadata
    confidence = models.FloatField(default=1.0)  # Confidence in this context item
    source_message_id = models.BigIntegerField(null=True, blank=True)  # Message that created this context
    expires_at = models.DateTimeField(null=True, blank=True)  # Optional expiration
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'conversation_context'
        indexes = [
            models.Index(fields=['session_id', 'context_type']),
            models.Index(fields=['user_id', 'context_type']),
            models.Index(fields=['key', 'session_id']),
            models.Index(fields=['expires_at']),
        ]
        unique_together = ['session_id', 'context_type', 'key']
    
    def __str__(self):
        return f"{self.context_type}: {self.key} = {self.value}"
    
    @property
    def is_expired(self) -> bool:
        """Check if this context item has expired"""
        return self.expires_at and timezone.now() > self.expires_at
    
    @classmethod
    def cleanup_expired(cls):
        """Remove expired context items"""
        cls.objects.filter(expires_at__lt=timezone.now()).delete()
    
    @classmethod
    def get_context_for_session(cls, session_id: str) -> Dict[str, Any]:
        """Get all active context for a session as a dictionary"""
        context_items = cls.objects.filter(
            session_id=session_id
        ).exclude(expires_at__lt=timezone.now())
        
        context = {}
        for item in context_items:
            if item.context_type not in context:
                context[item.context_type] = {}
            context[item.context_type][item.key] = item.value
        
        return context
