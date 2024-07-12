# find . -path "*/migrations/*.py" -not -name "__init__.py" -delete






#!/bin/bash

# Function to remove all migration files
clean_migrations() {
    find . -path "*/migrations/*.py" -not -name "__init__.py" -delete
    find . -path "*/migrations/*.pyc"  -delete
}

# Function to apply migrations and initialize roles
migrate_and_init_roles() {
    python manage.py makemigrations
    python manage.py migrate

    python manage.py add_default_roles
    # python manage.py initialize_categories
}

# Main script
echo "Cleaning all migration files..."
clean_migrations

echo "Applying migrations..."
migrate_and_init_roles

echo "All done!"
