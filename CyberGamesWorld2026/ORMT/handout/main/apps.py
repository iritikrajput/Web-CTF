from django.apps import AppConfig
from django.db.backends.signals import connection_created
from django.dispatch import receiver

@receiver(connection_created)
def set_sqlite_pragma(sender, connection, **kwargs):
    if connection.vendor == "sqlite":
        with connection.cursor() as cursor:
            cursor.execute("PRAGMA case_sensitive_like = ON;")

class MainConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'main'
