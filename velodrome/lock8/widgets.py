from django.core.exceptions import ValidationError
from django_filters.widgets import BooleanWidget


class StrictBooleanWidget(BooleanWidget):
    def value_from_datadict(self, data, files, name):
        value = data.get(name, None)
        if value is None:
            return None
        value = super().value_from_datadict(data, files, name)
        if value is None:
            raise ValidationError({
                name: 'value must be True, true, 1, or False, false, 0'})
        return value
