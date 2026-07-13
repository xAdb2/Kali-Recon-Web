#!/usr/bin/env python
"""Convenience wrapper: create/update the initial admin via Django.

Prefer `python manage.py create_admin` (this just forwards to it so the
documented scripts/create-admin.py path works too).
"""
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django

    django.setup()
    from django.core.management import call_command

    call_command("create_admin", *sys.argv[1:])
