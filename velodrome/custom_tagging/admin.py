from django.contrib import admin

from .forms import TagDeclarationForm
from .models import TagDeclaration, TagGroup


@admin.register(TagGroup)
class TagGroupAdmin(admin.ModelAdmin):

    list_display = (
        'id',
        'name',
        'description',
    )

    list_display_links = (
        'id',
    )


@admin.register(TagDeclaration)
class TagDeclarationAdmin(admin.ModelAdmin):
    form = TagDeclarationForm
    list_display = (
        'id',
        'name',
        'description',
        'group',
        'organization',
    )

    list_display_links = (
        'id',
        'group',
        'organization',
    )

    list_filter = (
        'group',
    )
