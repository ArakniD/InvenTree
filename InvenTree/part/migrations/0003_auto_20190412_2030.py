# Generated by Django 2.2 on 2019-04-12 10:30

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('part', '0002_part_default_location'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bomitem',
            name='part',
            field=models.ForeignKey(limit_choices_to={'buildable': True}, on_delete=django.db.models.deletion.CASCADE, related_name='bom_items', to='part.Part'),
        ),
    ]