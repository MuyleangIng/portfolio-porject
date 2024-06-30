from django.core.management.base import BaseCommand
from portfolio.models import Role


class Command(BaseCommand):
    help = 'Initialize default roles'

    def handle(self, *args, **kwargs):
        roles = ['user', 'admin']
        for role in roles:
            Role.objects.get_or_create(name=role)
        self.stdout.write(self.style.SUCCESS('Successfully initialized roles'))
