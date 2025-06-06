"""
Action Executor for AI Assistant

This module handles the execution of actions identified by the AI assistant,
including booking management, customer operations, and service/equipment management.
Provides integration with other Django apps and maintains data consistency.
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from django.db import transaction
from django.utils import timezone
from django.core.exceptions import ValidationError

from users.authentication import SupabaseUser

logger = logging.getLogger(__name__)


class ActionExecutor:
    """
    Executes actions identified by the AI assistant.
    Integrates with Calendar Management, Customer Management, and Service Catalog apps.
    """
    
    def __init__(self):
        self.action_handlers = {
            'create_booking': self._handle_create_booking,
            'update_booking': self._handle_update_booking,
            'cancel_booking': self._handle_cancel_booking,
            'reschedule_booking': self._handle_reschedule_booking,
            'check_availability': self._handle_check_availability,
            'create_customer': self._handle_create_customer,
            'update_customer': self._handle_update_customer,
            'search_customer': self._handle_search_customer,
            'get_customer_history': self._handle_get_customer_history,
            'create_service': self._handle_create_service,
            'update_service': self._handle_update_service,
            'create_equipment': self._handle_create_equipment,
            'update_equipment': self._handle_update_equipment,
        }
    
    def execute_action(self, action_type: str, parameters: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """
        Execute an action with the given parameters.
        
        Args:
            action_type: Type of action to execute
            parameters: Action parameters
            user_id: ID of the user requesting the action
        
        Returns:
            Dictionary containing action result and any created/modified object data
        """
        try:
            with transaction.atomic():
                # Validate user permissions (placeholder for now)
                self._validate_user_permissions(user_id, action_type, parameters)
                
                # Get action handler
                handler = self.action_handlers.get(action_type)
                if not handler:
                    raise ValueError(f"Unknown action type: {action_type}")
                
                # Execute action
                result = handler(parameters, user_id)
                
                # Log successful action
                logger.info(f"Action {action_type} executed successfully for user {user_id}")
                
                return {
                    "success": True,
                    "action_type": action_type,
                    "result": result,
                    "message": f"Successfully executed {action_type}"
                }
                
        except Exception as e:
            logger.error(f"Action execution failed for {action_type}: {e}")
            return {
                "success": False,
                "action_type": action_type,
                "error": str(e),
                "message": f"Failed to execute {action_type}: {str(e)}"
            }
    
    def _validate_user_permissions(self, user_id: str, action_type: str, parameters: Dict[str, Any]):
        """Validate user permissions for the action (placeholder for now)."""
        # TODO: Implement proper permission checking
        # For now, we assume all authenticated users can perform all actions on their own data
        pass
    
    # Booking Management Actions
    
    def _handle_create_booking(self, parameters: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Handle booking creation."""
        # TODO: This will integrate with the actual Calendar Management app
        # For now, creating a placeholder structure
        
        required_fields = ['customer_name', 'start_date']
        missing_fields = [field for field in required_fields if field not in parameters]
        if missing_fields:
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
        
        # Parse dates
        start_date = self._parse_date(parameters['start_date'])
        end_date = self._parse_date(parameters.get('end_date', parameters['start_date']))
        
        # If end_date is the same as start_date, add duration
        if start_date == end_date and 'duration' in parameters:
            duration_days = self._parse_duration(parameters['duration'])
            end_date = start_date + timedelta(days=duration_days)
        
        # Create booking data structure (this will be replaced with actual model creation)
        booking_data = {
            "id": f"booking_{timezone.now().strftime('%Y%m%d_%H%M%S')}",
            "user_id": user_id,
            "customer_name": parameters['customer_name'],
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "equipment": parameters.get('equipment', []),
            "services": parameters.get('services', []),
            "status": "confirmed",
            "notes": parameters.get('notes', ''),
            "created_at": timezone.now().isoformat()
        }
        
        # TODO: Replace with actual booking creation
        # booking = Booking.objects.create(**booking_data)
        
        return {
            "booking": booking_data,
            "message": f"Created booking for {parameters['customer_name']} from {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"
        }
    
    def _handle_update_booking(self, parameters: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Handle booking updates."""
        booking_id = parameters.get('booking_id')
        if not booking_id:
            raise ValueError("Booking ID is required for updates")
        
        # TODO: Replace with actual booking update
        # booking = Booking.objects.get(id=booking_id, user_id=user_id)
        # Update booking fields based on parameters
        
        update_fields = []
        for field in ['start_date', 'end_date', 'equipment', 'services', 'notes']:
            if field in parameters:
                update_fields.append(field)
        
        if not update_fields:
            raise ValueError("No fields provided for update")
        
        return {
            "booking_id": booking_id,
            "updated_fields": update_fields,
            "message": f"Updated booking {booking_id} with fields: {', '.join(update_fields)}"
        }
    
    def _handle_cancel_booking(self, parameters: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Handle booking cancellation."""
        booking_id = parameters.get('booking_id')
        if not booking_id:
            raise ValueError("Booking ID is required for cancellation")
        
        # TODO: Replace with actual booking cancellation
        # booking = Booking.objects.get(id=booking_id, user_id=user_id)
        # booking.status = 'cancelled'
        # booking.save()
        
        return {
            "booking_id": booking_id,
            "status": "cancelled",
            "message": f"Cancelled booking {booking_id}"
        }
    
    def _handle_reschedule_booking(self, parameters: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Handle booking rescheduling."""
        booking_id = parameters.get('booking_id')
        new_start_date = parameters.get('new_start_date')
        
        if not booking_id or not new_start_date:
            raise ValueError("Booking ID and new start date are required for rescheduling")
        
        start_date = self._parse_date(new_start_date)
        end_date = start_date
        
        if 'new_end_date' in parameters:
            end_date = self._parse_date(parameters['new_end_date'])
        elif 'duration' in parameters:
            duration_days = self._parse_duration(parameters['duration'])
            end_date = start_date + timedelta(days=duration_days)
        
        # TODO: Replace with actual booking rescheduling
        # booking = Booking.objects.get(id=booking_id, user_id=user_id)
        # booking.start_date = start_date
        # booking.end_date = end_date
        # booking.save()
        
        return {
            "booking_id": booking_id,
            "new_start_date": start_date.isoformat(),
            "new_end_date": end_date.isoformat(),
            "message": f"Rescheduled booking {booking_id} to {start_date.strftime('%Y-%m-%d')}"
        }
    
    def _handle_check_availability(self, parameters: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Handle availability checking."""
        start_date = self._parse_date(parameters.get('start_date', 'today'))
        end_date = self._parse_date(parameters.get('end_date', parameters.get('start_date', 'today')))
        equipment_list = parameters.get('equipment', [])
        
        # TODO: Replace with actual availability checking
        # This would query the booking system for conflicts
        
        availability_data = {
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat()
            },
            "equipment_availability": {},
            "available_slots": [],
            "conflicts": []
        }
        
        # Mock availability data
        for equipment in equipment_list:
            availability_data["equipment_availability"][equipment] = {
                "available": True,
                "conflicts": [],
                "available_periods": [
                    {
                        "start": start_date.isoformat(),
                        "end": end_date.isoformat()
                    }
                ]
            }
        
        return {
            "availability": availability_data,
            "message": f"Checked availability for {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"
        }
    
    # Customer Management Actions
    
    def _handle_create_customer(self, parameters: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Handle customer creation."""
        required_fields = ['name']
        missing_fields = [field for field in required_fields if field not in parameters]
        if missing_fields:
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
        
        # TODO: Replace with actual customer creation
        # customer = Customer.objects.create(
        #     user_id=user_id,
        #     name=parameters['name'],
        #     email=parameters.get('email', ''),
        #     phone=parameters.get('phone', ''),
        #     address=parameters.get('address', ''),
        #     notes=parameters.get('notes', '')
        # )
        
        customer_data = {
            "id": f"customer_{timezone.now().strftime('%Y%m%d_%H%M%S')}",
            "user_id": user_id,
            "name": parameters['name'],
            "email": parameters.get('email', ''),
            "phone": parameters.get('phone', ''),
            "address": parameters.get('address', ''),
            "notes": parameters.get('notes', ''),
            "created_at": timezone.now().isoformat()
        }
        
        return {
            "customer": customer_data,
            "message": f"Created customer: {parameters['name']}"
        }
    
    def _handle_update_customer(self, parameters: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Handle customer updates."""
        customer_id = parameters.get('customer_id')
        customer_name = parameters.get('customer_name')
        
        if not customer_id and not customer_name:
            raise ValueError("Customer ID or name is required for updates")
        
        # TODO: Replace with actual customer lookup and update
        # if customer_id:
        #     customer = Customer.objects.get(id=customer_id, user_id=user_id)
        # else:
        #     customer = Customer.objects.get(name__icontains=customer_name, user_id=user_id)
        
        update_fields = []
        for field in ['name', 'email', 'phone', 'address', 'notes']:
            if field in parameters:
                update_fields.append(field)
        
        if not update_fields:
            raise ValueError("No fields provided for update")
        
        return {
            "customer_id": customer_id or "found_by_name",
            "updated_fields": update_fields,
            "message": f"Updated customer with fields: {', '.join(update_fields)}"
        }
    
    def _handle_search_customer(self, parameters: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Handle customer search."""
        search_term = parameters.get('search_term', '')
        if not search_term:
            raise ValueError("Search term is required")
        
        # TODO: Replace with actual customer search
        # customers = Customer.objects.filter(
        #     user_id=user_id,
        #     name__icontains=search_term
        # )
        
        # Mock search results
        mock_customers = [
            {
                "id": "customer_1",
                "name": "John Smith",
                "email": "john@example.com",
                "phone": "+1234567890",
                "booking_count": 5
            },
            {
                "id": "customer_2", 
                "name": "Jane Doe",
                "email": "jane@example.com",
                "phone": "+1234567891",
                "booking_count": 3
            }
        ]
        
        # Filter by search term
        filtered_customers = [
            c for c in mock_customers 
            if search_term.lower() in c['name'].lower()
        ]
        
        return {
            "customers": filtered_customers,
            "count": len(filtered_customers),
            "search_term": search_term,
            "message": f"Found {len(filtered_customers)} customers matching '{search_term}'"
        }
    
    def _handle_get_customer_history(self, parameters: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Handle getting customer booking history."""
        customer_id = parameters.get('customer_id')
        customer_name = parameters.get('customer_name')
        
        if not customer_id and not customer_name:
            raise ValueError("Customer ID or name is required")
        
        # TODO: Replace with actual booking history query
        # bookings = Booking.objects.filter(
        #     user_id=user_id,
        #     customer_id=customer_id
        # ).order_by('-start_date')
        
        # Mock booking history
        mock_history = [
            {
                "id": "booking_1",
                "start_date": "2024-03-01",
                "end_date": "2024-03-03",
                "equipment": ["Camera A", "Lens Kit"],
                "status": "completed",
                "total_amount": 150.00
            },
            {
                "id": "booking_2",
                "start_date": "2024-02-15",
                "end_date": "2024-02-16",
                "equipment": ["Camera B"],
                "status": "completed",
                "total_amount": 75.00
            }
        ]
        
        return {
            "customer_id": customer_id,
            "booking_history": mock_history,
            "total_bookings": len(mock_history),
            "message": f"Retrieved booking history for customer"
        }
    
    # Service/Equipment Management Actions
    
    def _handle_create_service(self, parameters: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Handle service creation."""
        required_fields = ['name', 'price']
        missing_fields = [field for field in required_fields if field not in parameters]
        if missing_fields:
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
        
        # TODO: Replace with actual service creation
        service_data = {
            "id": f"service_{timezone.now().strftime('%Y%m%d_%H%M%S')}",
            "user_id": user_id,
            "name": parameters['name'],
            "description": parameters.get('description', ''),
            "price": float(parameters['price']),
            "duration": parameters.get('duration', 1),
            "category": parameters.get('category', 'general'),
            "created_at": timezone.now().isoformat()
        }
        
        return {
            "service": service_data,
            "message": f"Created service: {parameters['name']}"
        }
    
    def _handle_update_service(self, parameters: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Handle service updates."""
        service_id = parameters.get('service_id')
        service_name = parameters.get('service_name')
        
        if not service_id and not service_name:
            raise ValueError("Service ID or name is required for updates")
        
        update_fields = []
        for field in ['name', 'description', 'price', 'duration', 'category']:
            if field in parameters:
                update_fields.append(field)
        
        if not update_fields:
            raise ValueError("No fields provided for update")
        
        return {
            "service_id": service_id or "found_by_name",
            "updated_fields": update_fields,
            "message": f"Updated service with fields: {', '.join(update_fields)}"
        }
    
    def _handle_create_equipment(self, parameters: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Handle equipment creation."""
        required_fields = ['name']
        missing_fields = [field for field in required_fields if field not in parameters]
        if missing_fields:
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
        
        # TODO: Replace with actual equipment creation
        equipment_data = {
            "id": f"equipment_{timezone.now().strftime('%Y%m%d_%H%M%S')}",
            "user_id": user_id,
            "name": parameters['name'],
            "description": parameters.get('description', ''),
            "category": parameters.get('category', 'camera'),
            "daily_rate": float(parameters.get('daily_rate', 0)),
            "quantity": int(parameters.get('quantity', 1)),
            "status": "available",
            "created_at": timezone.now().isoformat()
        }
        
        return {
            "equipment": equipment_data,
            "message": f"Created equipment: {parameters['name']}"
        }
    
    def _handle_update_equipment(self, parameters: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Handle equipment updates."""
        equipment_id = parameters.get('equipment_id')
        equipment_name = parameters.get('equipment_name')
        
        if not equipment_id and not equipment_name:
            raise ValueError("Equipment ID or name is required for updates")
        
        update_fields = []
        for field in ['name', 'description', 'category', 'daily_rate', 'quantity', 'status']:
            if field in parameters:
                update_fields.append(field)
        
        if not update_fields:
            raise ValueError("No fields provided for update")
        
        return {
            "equipment_id": equipment_id or "found_by_name",
            "updated_fields": update_fields,
            "message": f"Updated equipment with fields: {', '.join(update_fields)}"
        }
    
    # Utility Methods
    
    def _parse_date(self, date_input: str) -> datetime:
        """Parse various date formats and relative date expressions."""
        from dateutil import parser
        import re
        
        if not date_input:
            return timezone.now().date()
        
        # Handle relative dates
        date_input = date_input.lower().strip()
        
        if date_input == 'today':
            return timezone.now().date()
        elif date_input == 'tomorrow':
            return (timezone.now() + timedelta(days=1)).date()
        elif date_input == 'yesterday':
            return (timezone.now() - timedelta(days=1)).date()
        elif 'next monday' in date_input:
            # Calculate next Monday
            today = timezone.now().date()
            days_ahead = 0 - today.weekday()  # Monday is 0
            if days_ahead <= 0:  # Target day already happened this week
                days_ahead += 7
            return today + timedelta(days_ahead)
        elif 'next' in date_input:
            # Handle other "next" day patterns
            days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
            for i, day in enumerate(days):
                if day in date_input:
                    today = timezone.now().date()
                    days_ahead = i - today.weekday()
                    if days_ahead <= 0:
                        days_ahead += 7
                    return today + timedelta(days_ahead)
        
        # Try to parse as standard date
        try:
            parsed_date = parser.parse(date_input)
            return parsed_date.date()
        except:
            # If all else fails, return today
            logger.warning(f"Could not parse date: {date_input}, using today")
            return timezone.now().date()
    
    def _parse_duration(self, duration_input: str) -> int:
        """Parse duration expressions into number of days."""
        if not duration_input:
            return 1
        
        duration_input = duration_input.lower().strip()
        
        # Extract number and unit
        import re
        match = re.search(r'(\d+)\s*(day|days|week|weeks|month|months)?', duration_input)
        
        if match:
            number = int(match.group(1))
            unit = match.group(2) or 'day'
            
            if 'week' in unit:
                return number * 7
            elif 'month' in unit:
                return number * 30  # Approximate
            else:
                return number
        
        # Default to 1 day
        return 1 