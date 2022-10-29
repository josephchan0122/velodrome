from django.forms import ModelForm
from django.forms.widgets import TextInput

from .models import TagDeclaration


class TagDeclarationForm(ModelForm):
    class Meta:
        model = TagDeclaration
        fields = '__all__'
        widgets = {
            'color': TextInput(attrs={'type': 'color'}),
        }
