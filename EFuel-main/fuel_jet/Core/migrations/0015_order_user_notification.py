# Generated by Django 5.2.4 on 2025-07-03 15:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Core', '0014_alter_order_latitude_alter_order_longitude'),
    ]

    operations = [
        migrations.AddField(
            model_name='order',
            name='user_notification',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
