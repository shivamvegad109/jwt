from django.urls import path
from .views import RegisterView, LoginView, UserView, logout, ChangePasswordView
from . import views 

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('user/', UserView.as_view()),
    path('logout/', logout,name='logout'),
    path('change_password/', ChangePasswordView.as_view(), name='change-password'),
     
]