# Chedula Backend

The backend service for Chedula, an AI-powered scheduling application built with Django and Django REST Framework. This service handles business logic, API endpoints, and integrations with various services.

## Tech Stack

- **Framework**: Django + Django REST Framework
- **Database**: PostgreSQL (via Supabase)
- **Authentication**: Supabase Auth
- **Real-time**: Django Channels
- **Task Queue**: Celery
- **AI Integration**: OpenRouter API
- **Payment Processing**: Paymongo

## Prerequisites

- Python 3.8+
- PostgreSQL
- Redis (for Celery)
- Docker (optional)

## Setup

1. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
Create a `.env` file in the root directory with the following variables:
```env
DEBUG=True
SECRET_KEY=your-secret-key
DATABASE_URL=your-supabase-database-url
SUPABASE_URL=your-supabase-url
SUPABASE_KEY=your-supabase-key
OPENROUTER_API_KEY=your-openrouter-api-key
PAYMONGO_SECRET_KEY=your-paymongo-secret-key
```

4. Run migrations:
```bash
python manage.py migrate
```

5. Create a superuser:
```bash
python manage.py createsuperuser
```

## Development

1. Start the development server:
```bash
python manage.py runserver
```

2. Start Celery worker (in a separate terminal):
```bash
celery -A core worker -l info
```

3. Start Celery beat for scheduled tasks (in a separate terminal):
```bash
celery -A core beat -l info
```

## API Documentation

The API documentation is available at `/api/docs/` when running the development server. The API follows RESTful principles and is versioned (v1).

## Testing

Run tests using Django's test framework:
```bash
python manage.py test
```

## Docker Deployment

1. Build the Docker image:
```bash
docker build -t chedula-backend .
```

2. Run the container:
```bash
docker run -p 8000:8000 chedula-backend
```

## Project Structure

```
backend/
├── src/
│   ├── api/          # REST API endpoints
│   ├── core/         # Core Django settings
│   ├── users/        # User management
│   ├── ai_assistant/ # AI integration
│   ├── calendar_mgmt/# Calendar management
│   ├── contracts/    # Contract generation
│   ├── notifications/# Email/notification system
│   └── payments/     # Payment integration
├── staticfiles/      # Static files
├── templates/        # HTML templates
├── requirements.txt  # Python dependencies
└── Dockerfile       # Docker configuration
```

## Security Considerations

- All API endpoints require authentication
- JWT tokens are validated on the backend
- Input validation is performed on all endpoints
- CSRF protection is enabled
- Rate limiting is implemented on sensitive endpoints

## Contributing

1. Follow PEP 8 style guide
2. Write tests for new features
3. Update documentation as needed
4. Use conventional commits format

## License

[Your License Here] 