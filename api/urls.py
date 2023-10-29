from django.urls import path
from .views import NagadPaymentView

urlpatterns = [
    path('nagad/', NagadPaymentView.as_view(), name='nagad'),
]
