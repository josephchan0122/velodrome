from django.urls import path

from .views import RulesAccessView

urlpatterns = [
    path(r"rules-access", RulesAccessView.as_view(), name="rules-access"),
]
