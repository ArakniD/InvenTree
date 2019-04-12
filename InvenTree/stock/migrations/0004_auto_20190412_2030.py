# Generated by Django 2.2 on 2019-04-12 10:30

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('stock', '0003_auto_20180510_1042'),
    ]

    operations = [
        migrations.AlterField(
            model_name='stockitem',
            name='status',
            field=models.PositiveIntegerField(choices=[(10, 'OK'), (50, 'Attention needed'), (55, 'Damaged'), (60, 'Destroyed')], default=10, validators=[django.core.validators.MinValueValidator(0)]),
        ),
    ]
