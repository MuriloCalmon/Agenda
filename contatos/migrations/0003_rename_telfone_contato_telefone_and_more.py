# Generated by Django 4.0.2 on 2022-02-25 00:30

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('contatos', '0002_alter_contato_data_criacao'),
    ]

    operations = [
        migrations.RenameField(
            model_name='contato',
            old_name='telfone',
            new_name='telefone',
        ),
        migrations.AlterField(
            model_name='contato',
            name='data_criacao',
            field=models.DateTimeField(default=datetime.datetime(2022, 2, 25, 0, 30, 11, 229855, tzinfo=utc)),
        ),
    ]
