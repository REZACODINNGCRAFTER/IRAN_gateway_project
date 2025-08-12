# IRAN_gateway_project

A secure, scalable, and modular Django-based web application designed for modern API-driven development. This project includes a professional configuration for multiple environments, robust security practices, and comprehensive test coverage.

## Features

* ✅ Django 4.x with environment-based settings (`dev`, `prod`)
* 🔒 Integrated security modules (rate-limiting, CAPTCHA, geoIP, OTP)
* 🌍 RESTful APIs with `django-rest-framework`
* 📦 Modular structure (`gateway`, `accounts`, `api_gateway`)
* 🧪 Pytest and unit test coverage
* 🧰 Logging, throttling, and monitoring support
* 🌐 Deployment-ready with ASGI and WSGI

## Getting Started

### Prerequisites

* Python 3.8+
* PostgreSQL or SQLite
* Pipenv or virtualenv

### Installation

```bash
# Clone the repository
$ git clone https://github.com/REZACODINNGCRAFTER/IRAN_gateway_project.git
$ cd project-name

# Set up virtual environment
$ python -m venv venv
$ source venv/bin/activate

# Install dependencies
$ pip install -r requirements.txt

# Set environment variables
$ cp .env.example .env
$ python manage.py migrate
$ python manage.py runserver
```

### Project Structure

```
project_name/
├── accounts/               # User auth & management
├── api_gateway/            # API-specific logic and serializers
├── components/             # Logging, security, DRF configs
├── config/                 # Settings, URLs, ASGI/WSGI entry points
├── gateway/                # Web views and site logic
├── security/               # Captcha, OTP, rate-limiting, etc.
├── templates/              # HTML templates
├── tests/                  # Unit & integration tests
└── manage.py               # Django admin utility
```

## Configuration

* `config/settings/base.py` - Shared settings
* `config/settings/dev.py` - Development settings
* `config/settings/prod.py` - Production settings
* `.env` - Environment variables (see `.env.example`)

## Testing

```bash
$ python manage.py test
```

## Linting and Formatting

```bash
$ flake8 .
$ black .
```

## License

This project is licensed under the MIT License.

## Contributors

* [Your Name](https://github.com/your-username) - Lead Developer

---

> For contributions, issues, or questions, please open an issue or submit a pull request.
