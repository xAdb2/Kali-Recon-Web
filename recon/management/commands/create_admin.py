"""Idempotently create/update the initial admin superuser from env or flags.

Never embeds a default password. If no password is provided a strong random
one is generated and printed exactly once.
"""
from __future__ import annotations

import os
import secrets

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Create or update the initial admin superuser (idempotent)."

    def add_arguments(self, parser):
        parser.add_argument("--username", default=os.environ.get("ADMIN_USERNAME", "admin"))
        parser.add_argument("--email", default=os.environ.get("ADMIN_EMAIL", ""))
        parser.add_argument("--password", default=os.environ.get("ADMIN_PASSWORD", ""))

    def handle(self, *args, **opts):
        User = get_user_model()
        username = opts["username"]
        email = opts["email"]
        provided = opts["password"]

        user, created = User.objects.get_or_create(
            username=username, defaults={"email": email}
        )
        user.is_staff = True
        user.is_superuser = True
        if email:
            user.email = email

        generated = False
        if provided:
            user.set_password(provided)
        elif created:
            # New user, no password supplied: mint a one-time random password.
            random_pw = secrets.token_urlsafe(18)
            user.set_password(random_pw)
            generated = True
        # Existing user without an explicit password: leave the password intact.
        user.save()

        action = "建立" if created else "更新"
        self.stdout.write(self.style.SUCCESS(f"已{action}管理員帳號：{username}"))
        if generated:
            self.stdout.write(
                self.style.WARNING(
                    f"一次性隨機密碼（請立即保存）：{random_pw}"
                )
            )
