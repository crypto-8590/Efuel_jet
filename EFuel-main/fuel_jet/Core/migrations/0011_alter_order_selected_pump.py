# Generated by Django 5.2 on 2025-06-23 14:48

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Core', '0010_petrolpump_agent'),
    ]

    operations = [
        migrations.AlterField(
            model_name='order',
            name='selected_pump',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Core.petrolpump'),
        ),
    ]
