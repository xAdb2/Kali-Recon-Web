from django.conf import settings


def site_flags(request):
    """Expose global flags to every template."""
    return {
        "ENABLE_EXPERT_COMMANDS": settings.KALIRECON["ENABLE_EXPERT_COMMANDS"],
        "SITE_NAME": "KaliRecon Web",
    }
