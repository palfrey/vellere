# Generated by Django 2.1.7 on 2019-03-21 16:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('notifier', '0002_auto_20190321_1421'),
    ]

    operations = [
        migrations.AddField(
            model_name='organisation',
            name='login',
            field=models.CharField(default='', max_length=255, unique=True),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='repository',
            name='name',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
    ]
