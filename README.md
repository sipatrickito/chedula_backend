# Chedula Backend

AI-powered scheduling application backend built with Django. This guide will help you set up the development environment using Docker.

## 🛠️ Tech Stack

- **Framework**: Django 5.2+ with Django REST Framework
- **Database**: PostgreSQL (via Supabase)
- **Cache & Sessions**: Redis 7.0+
- **Authentication**: Supabase Auth with JWT
- **Real-time**: Django Channels (WebSocket support)
- **Task Queue**: Celery with Redis broker
- **AI Integration**: OpenRouter API
- **Payment Processing**: Paymongo
- **API Documentation**: DRF Spectacular (OpenAPI 3.0)

## 📋 Prerequisites

- **Docker Desktop** installed and running
- **Git** for version control
- **Code editor** (VS Code recommended)
- **Supabase account** (for database and authentication)
- **OpenRouter account** (for AI features)

## 🚀 Quick Setup (5 minutes)

### 1. Clone and Navigate to Backend
```bash
git clone <repository-url>
cd chedula/backend
```

### 2. Create Environment File
Create a `.env` file in the backend directory with these exact credentials:

# Django Configuration
DJANGO_SECRET_KEY=your-super-secret-key-change-this-in-production-min-50-chars
DJANGO_DEBUG=True
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0

# Database Configuration (Supabase PostgreSQL)
# Get these from your Supabase project settings > Database
DB_NAME=postgres
DB_USER=postgres.your-project-ref
DB_PASSWORD=your-database-password
DB_HOST=db.your-project-ref.supabase.co
DB_PORT=5432

# Supabase Configuration
# Get these from your Supabase project settings > API
SUPABASE_URL=https://your-project-ref.supabase.co
SUPABASE_ANON_KEY=your-supabase-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-supabase-service-role-key
SUPABASE_JWT_SECRET=your-supabase-jwt-secret

# Redis Configuration (handled by Docker Compose)
REDIS_URL=redis://redis:6379/0

# AI Integration (OpenRouter)
# Sign up at https://openrouter.ai/ and get your API key
OPENROUTER_API_KEY=your-openrouter-api-key

# Payment Processing (Paymongo - Optional for now)
# Sign up at https://paymongo.com for production keys
PAYMONGO_SECRET_KEY=sk_test_your-paymongo-secret-key
PAYMONGO_PUBLIC_KEY=pk_test_your-paymongo-public-key

# Email Configuration (Optional - for notifications)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# Development URLs
FRONTEND_URL=http://localhost:3000
BACKEND_URL=http://localhost:8000 

> **Note**: These are shared development credentials. In production, each teammate would have their own environment variables.

### 3. Start the Development Environment
```bash
# Build and start all services
docker-compose up --build

# Or run in background (detached mode)
docker-compose up -d --build
```

### 4. Verify Everything is Working
After containers start (takes 2-3 minutes on first run), you should see:

- ✅ **API Health**: http://localhost:8000/api/health/ → `{"status": "healthy"}`
- ✅ **API Root**: http://localhost:8000/api/
- ✅ **Admin Panel**: http://localhost:8000/admin/
- ✅ **API Docs**: http://localhost:8000/api/docs/
- ✅ **ReDoc**: http://localhost:8000/api/redoc/

**Success indicators in logs:**
```bash
web-1            | Starting Django development server...
web-1            | Starting development server at http://0.0.0.0:8000/
redis-1          | Ready to accept connections tcp
celery_worker-1  | celery@container ready.
celery_beat-1    | beat: Starting...
```

## 🐳 Docker Services

Your development environment includes:

| Service | Purpose | Port | Status Check |
|---------|---------|------|--------------|
| **web** | Django API server | 8000 | http://localhost:8000/api/health/ |
| **redis** | Cache & session storage | 6379 | `docker-compose exec redis redis-cli ping` |
| **celery_worker** | Background tasks | - | Check logs for "ready" |
| **celery_beat** | Scheduled tasks | - | Check logs for "Starting..." |

## 🔧 Common Commands

### Docker Management
```bash
# View running containers
docker-compose ps

# View logs (useful for debugging)
docker-compose logs web          # Django app logs
docker-compose logs redis        # Redis logs
docker-compose logs celery_worker # Background task logs
docker-compose logs -f           # Follow all logs

# Stop all services
docker-compose down

# Rebuild specific service
docker-compose build web

# Clean restart (if things get stuck)
docker-compose down && docker-compose up --build

# Remove everything and start fresh
docker-compose down -v && docker-compose up --build
```

### Django Management
```bash
# Run database migrations
docker-compose exec web python src/manage.py migrate

# Create superuser (for admin panel)
docker-compose exec web python src/manage.py createsuperuser

# Django shell (for testing)
docker-compose exec web python src/manage.py shell

# Run tests
docker-compose exec web python src/manage.py test

# Check if models need migrations
docker-compose exec web python src/manage.py makemigrations --dry-run
```

### Development Workflow
```bash
# Make code changes in ./src/ - they automatically reload!
# No restart needed for Python code changes

# If you add new Python packages to requirements.txt:
docker-compose build web

# If you change Django models:
docker-compose exec web python src/manage.py makemigrations
docker-compose exec web python src/manage.py migrate

# If you change settings or Docker configs:
docker-compose down && docker-compose up --build
```

## 📁 Project Structure

```
backend/
├── src/                      # Main source code (auto-reloads in Docker)
│   ├── core/                 # Django project settings
│   │   ├── settings.py       # Main configuration
│   │   ├── urls.py          # Root URL routing
│   │   ├── celery.py        # Celery configuration
│   │   └── asgi.py          # WebSocket support
│   ├── api/                  # Main API endpoints
│   ├── users/                # Authentication & user management
│   ├── ai_assistant/         # AI chat integration
│   ├── calendar_mgmt/        # Calendar and booking system
│   ├── contracts/            # Contract generation
│   ├── notifications/        # Email/SMS notifications
│   ├── payments/             # Payment processing
│   └── utils/                # Shared utilities
├── docker-compose.yml        # Container orchestration
├── Dockerfile               # Python environment setup
├── requirements.txt          # Python dependencies
├── .env                     # Your environment variables (create this!)
├── .dockerignore            # Docker build optimization
└── staticfiles/             # Collected static files
```

## 🧪 Testing & Quality

### Running Tests
```bash
# Run all tests
docker-compose exec web python src/manage.py test

# Run specific app tests
docker-compose exec web python src/manage.py test users
docker-compose exec web python src/manage.py test ai_assistant

# Run with verbose output
docker-compose exec web python src/manage.py test --verbosity=2

# Run tests with coverage (if configured)
docker-compose exec web coverage run src/manage.py test
docker-compose exec web coverage report
```

### Code Quality
```bash
# Django system checks
docker-compose exec web python src/manage.py check

# Check for missing migrations
docker-compose exec web python src/manage.py makemigrations --dry-run --check
```

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Find what's using port 8000
# Windows: netstat -ano | findstr :8000
# macOS/Linux: lsof -i :8000

# Change port in docker-compose.yml if needed:
# ports: - "8001:8000"  # Use port 8001 instead
```

### Database Connection Issues
1. **Check .env file** has correct credentials
2. **Verify Supabase project** is active (not paused)
3. **Test connection**:
   ```bash
   docker-compose exec web python src/manage.py dbshell
   ```
4. **Check logs**: `docker-compose logs web`

### Redis Connection Issues
```bash
# Check Redis container
docker-compose logs redis

# Test Redis manually
docker-compose exec redis redis-cli ping
# Should return: PONG
```

### Container Build Issues
```bash
# Clean everything and rebuild
docker-compose down -v
docker system prune -f
docker-compose up --build

# If Docker Desktop issues:
# Restart Docker Desktop
# Check Docker has enough resources (4GB RAM, 2 CPUs minimum)
```

### Common Error Solutions

**"Tenant or user not found"**
→ Database credentials incorrect. Check DB_USER format: `postgres.projectref`

**"Connection refused" (Redis)**
→ Redis container not running. Check: `docker-compose ps`

**"Port 8000 already in use"**
→ Another service using port. Stop it or change port in docker-compose.yml

**"No such file or directory: .env"**
→ Create .env file with credentials above

### Hot Reloading
- ✅ **Python code changes**: Automatic reload
- ✅ **Template changes**: Automatic reload  
- ❌ **Settings changes**: Restart required
- ❌ **New packages**: Rebuild required
- ❌ **Model changes**: Migration required

## 🚀 What's Next?

Once your environment is running:

1. **Create superuser**: `docker-compose exec web python src/manage.py createsuperuser`
2. **Explore admin panel**: http://localhost:8000/admin/
3. **Check API docs**: http://localhost:8000/api/docs/
4. **Start building features** per your task division

## 🔐 Security Notes

- **Development credentials**: Shared for team development only
- **Production setup**: Each environment needs unique credentials
- **API keys**: Never commit real API keys to git
- **Database**: Shared Supabase instance for team collaboration

## 📚 API Documentation

The API is automatically documented and available at:
- **Interactive docs**: http://localhost:8000/api/docs/
- **ReDoc format**: http://localhost:8000/api/redoc/
- **OpenAPI schema**: http://localhost:8000/api/schema/

## 🤝 Team Development

### Git Workflow
```bash
# Pull latest changes
git pull origin main

# Make your changes in src/

# Commit and push
git add .
git commit -m "feat: add new feature"
git push origin feature-branch
```

### Sharing Database
- All teammates share the same Supabase database
- Changes made by one person are visible to others
- Be careful with migrations and data changes

## 🆘 Getting Help

1. **Check logs first**: `docker-compose logs web`
2. **Review this troubleshooting section**
3. **Verify .env file** matches exactly
4. **Ask teammate** - share error logs if needed
5. **Restart fresh**: `docker-compose down && docker-compose up --build`
