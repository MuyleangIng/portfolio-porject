from django.contrib import admin
from django.urls import path, include
from portfolio import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.conf import settings
from django.conf.urls.static import static
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('portfolio.urls')),
    path('admin/', admin.site.urls),
    path('select-templates/', views.SelectTemplateListCreateView.as_view(), name='select-template-list-create'),
    path('select-templates/<int:pk>/', views.SelectTemplateDetailView.as_view(), name='select-template-detail'),
    path('<str:username>/<str:unique_slug>/', views.PublicPortfolioView.as_view(), name='public-portfolio-view'),

]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
