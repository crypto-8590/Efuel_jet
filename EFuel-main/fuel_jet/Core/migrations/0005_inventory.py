# Generated by Django 5.2 on 2025-05-22 07:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Core', '0004_payment'),
    ]

    operations = [
        migrations.CreateModel(
            name='Inventory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fuel_type', models.CharField(max_length=100)),
                ('quantity', models.PositiveIntegerField(default=0)),
            ],
        ),
    ]
