from django.contrib import admin
from django.urls import path
from main import views as u

urlpatterns = [
    path('', u.index),
    path('details', u.details),
    path('book_lookup', u.book_lookup),
    path('admin', u.admin),
]
