# Generated by Django 2.2 on 2019-05-08 13:32

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('build', '0011_auto_20190508_0748'),
    ]

    operations = [
        migrations.AlterField(
            model_name='build',
            name='notes',
            field=models.TextField(blank=True, help_text='Extra build notes'),
        ),
        migrations.AlterField(
            model_name='build',
            name='part',
            field=models.ForeignKey(help_text='Select part to build', limit_choices_to={'active': True, 'buildable': True}, on_delete=django.db.models.deletion.CASCADE, related_name='builds', to='part.Part'),
        ),
        migrations.AlterField(
            model_name='build',
            name='status',
            field=models.PositiveIntegerField(choices=[(10, 'Pending'), (20, 'Allocated'), (30, 'Cancelled'), (40, 'Complete')], default=10, help_text='Build status', validators=[django.core.validators.MinValueValidator(0)]),
        ),
    ]