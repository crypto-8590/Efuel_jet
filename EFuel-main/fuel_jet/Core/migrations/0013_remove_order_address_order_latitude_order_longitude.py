# Generated by Django 5.2.4 on 2025-07-03 07:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Core', '0012_alter_order_selected_pump'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='order',
            name='address',
        ),
        migrations.AddField(
            model_name='order',
            name='latitude',
            field=models.DecimalField(decimal_places=6, default=0.0, max_digits=9),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='order',
            name='longitude',
            field=models.DecimalField(decimal_places=6, default=0.0, max_digits=9),
            preserve_default=False,
        ),
    ]
