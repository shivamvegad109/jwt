from requests import request
from rest_framework.views import APIView
# from .serializer import Userserializer, ChangePasswordSerializer
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated,AllowAny
from .models import User
import jwt, datetime 
from rest_framework import generics,status
from django.contrib.auth import authenticate            
from .serializer import *
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view
from rest_framework_simplejwt.exceptions import TokenError



# from users.emails import send_otp_via_email

# from utils.weather import getweather
# from django.shortcuts import render
# Create your views here.

class RegisterView(generics.GenericAPIView):
    serializer_class = Userserializer
    def post(self, request):
        serializer = Userserializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
        
    
class LoginView(generics.GenericAPIView):
    
    serializer_class = LoginSerializer
    def post(self, request, *args, **kwargs):
        data = request.data
        email = data.get("email", "")
        password = data.get("password", "")
        user = authenticate(request, email=email, password=password)
        if user:
            serializer_class = self.get_serializer(data=request.data)
            if serializer_class.is_valid(raise_exception=True):
                user_data = {"user_id": user.id, "email":user.email, "tokens":user.token}
                message = "login_success"
                return Response({'message':message, 'data':user_data}, status=status.HTTP_200_OK)
        message = "Enter Email And Password "
        return Response({'message': message}, status=status.HTTP_401_UNAUTHORIZED)     
        
    
    
         
class UserView(generics.GenericAPIView):
    
    permission_classes = [IsAuthenticated,AllowAny]
    
    
    def get (self,request): 
        
        users = User.objects.all().exclude(is_staff=True).order_by("id")
        serializer = Userserializer(users, many=True)
        return Response(serializer.data)
    
# @api_view(["POST",])
# def logout_user(request):
#     refresh_token = request.data.get["refresh_token"]
#     token_obj= RefreshToken(refresh_token)
#     if request.method == "POST":
#         token_obj.delete()
#         return Response({"message":"you are logout"},status=status.HTTP_200_OK)

@api_view(['POST'])
# @csrf_exempt
def logout(request):
    try:
        refresh_token = request.data.get('refresh_token')
        token = RefreshToken(refresh_token)
        token.blacklist()

        return Response({'message': 'Logout successful.'}, status=status.HTTP_205_RESET_CONTENT)
    except Exception as e:
        return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)




class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)   
    
# class LogoutView(APIView):
#     # permission_classes = (IsAuthenticated,)

#     def post(self, request,format=None):
#         breakpoint()
# #         try:
#             refresh_token = request.data.get["refresh_token"]
#             token_obj= RefreshToken(refresh_token)
#             token_obj.blacklist()
#             return Response(status=status.HTTP_200)
#         except Exception as e:
#             return Response(status=status.HTTP_400_BAD_REQUEST)
    # def post (self,request):
    #     response = Response()
    #     response.delete_cookie('jwt')
    #     response.data = {
    #         'message':'success'
    #     }
    #     # elif token ==:
    #     #     raise AuthenticationFailed('PLZ....Re_Generate_Token..............')    
    #     return response
    
    

# class ChangePasswordView(generics.UpdateAPIView):
#     """
#     An endpoint for changing password.
#     """
#     serializer_class = ChangePasswordSerializer
#     model = User
#     # permission_classes = (IsAuthenticated,)

#     def get_object(self, queryset=None):
#         obj = self.request.user
#         return obj

#     def update(self, request, *args, **kwargs):
#         self.object = self.get_object()
#         serializer = self.get_serializer(data=request.data)

#         if serializer.is_valid():
#             # Check old password
#             if not self.object.check_password(serializer.data.get("old_password")):
#                 return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
#             # set_password also hashes the password that the user will get
#             self.object.set_password(serializer.data.get("new_password"))
#             self.object.save()
#             response = {
#                 'status': 'success',
#                 'code': status.HTTP_200_OK,
#                 'message': 'Password updated successfully',
#                 'data': []
#             }

#             return Response(response)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

# class LoginView(APIView):
#     def post(self, request):
#         email = request.data['email']
#         password = request.data['password']
#         # user = authenticate(User.objects.filter(email=email).first())
#         user = authenticate(request, email=email, password=password)
#         if user is None:
#             raise AuthenticationFailed('User not found')
        
#         if not user.check_password(password):
#             raise AuthenticationFailed(
#                 ('incorrect password'),
#             )     

#         payload = {
#             'id':user.id,
#             'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
#             'iat':datetime.datetime.utcnow()
#         }
#         token = jwt.encode(payload, 'secret', algorithm='HS256').decode('utf-8')
        
#         response = Response()
#         response.set_cookie(key='jwt', value=token, httponly=True)
#         response.data = ({
#             'jwt':token
#         })   
        
#         return response