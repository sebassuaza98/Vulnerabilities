from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView
from security.views import (
    VulnerabilityViewSet, add_vulnerability, list_vulnerabilities, summarize_by_severity, register_user
)

router = DefaultRouter()
router.register(r'vulnerabilities', VulnerabilityViewSet, basename='vulnerabilities')

urlpatterns = [
    path('', include(router.urls)),
    path('update-vulnerability/', add_vulnerability, name='update-vulnerability'),
    path('list-vulnerabilities/', list_vulnerabilities, name='list-vulnerabilities'),
    path('summarize-by-severity/', summarize_by_severity, name='summarize-by-severity'),
    path('api/register/', register_user, name='register_user'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
]
