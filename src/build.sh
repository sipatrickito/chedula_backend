#!/bin/bash

if [[ $CREATE_SUPERUSER ]]; then
  python src/manage.py createsuperuser --no-input || echo "Superuser creation skipped"
fi
