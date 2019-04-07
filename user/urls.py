from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from . import views

urlpatterns = [
    # path('user/', views.user_list),
    # path('user/<username>/', views.user_detail),
    path('register/', views.RegisterView.as_view()),
    path('login/', views.LoginView.as_view()),
    path('user/', views.UserDetailView.as_view()),
]

urlpatterns = format_suffix_patterns(urlpatterns)