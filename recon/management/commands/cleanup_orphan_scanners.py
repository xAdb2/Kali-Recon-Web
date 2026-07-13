from django.core.management.base import BaseCommand

from recon.services.docker_runner import cleanup_orphans


class Command(BaseCommand):
    help = "Remove orphaned KaliRecon scanner containers (by label)."

    def handle(self, *args, **options):
        removed = cleanup_orphans()
        self.stdout.write(self.style.SUCCESS(f"已清除 {removed} 個殘留掃描容器。"))
