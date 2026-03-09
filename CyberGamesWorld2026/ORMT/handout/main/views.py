from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from main.models import Book, Author, Review, SiteUser
import base64
import secrets
from functools import wraps
import json

def siteuser_basic_auth(required_role=None, realm="Restricted"):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            auth = request.META.get("HTTP_AUTHORIZATION", "")
            if auth.startswith("Basic "):
                try:
                    b64 = auth.split(" ", 1)[1].strip()
                    decoded = base64.b64decode(b64).decode("utf-8")
                    username, password = decoded.split(":", 1)

                    user = SiteUser.objects.filter(username=username).first()
                    if user and secrets.compare_digest(user.password, password):
                        if required_role is None or user.role == required_role:
                            request.site_user = user
                            return view_func(request, *args, **kwargs)
                except Exception:
                    pass
            resp = HttpResponse("Authentication required", status=401)
            resp["WWW-Authenticate"] = f'Basic realm="{realm}", charset="UTF-8"'
            return resp
        return _wrapped
    return decorator

def clean(filter, depth=0):
    if depth == 25:
        raise RecursionError
    if filter.find('__') != -1:
        return clean(filter.replace('__', '_', 1), depth+1)
    return filter.replace('_', '__', 1)

@csrf_exempt
def book_lookup(request):
    if request.method == 'GET':
        return render(request, 'lookup.html')
    if request.method == 'POST':
        filters = {}
        for filter in request.POST:
            if request.POST[filter] == '':
                continue
            try:
                filters[clean(filter)] = request.POST[filter]
            except: 
                filters[filter] = request.POST[filter]
        try:
            finds = Book.objects.filter(**filters)
        except Exception:
            return render(request, 'lookup.html')
        return render(request, 'lookup.html', {'books': finds})
    
def index(request):
    books = Book.objects.all()
    return render(request, 'index.html', {'books': books})

def details(request):
    id = request.GET.get('id', None)
    if id is None:
        return redirect('/')
    book = Book.objects.filter(id=id).first()
    if book is None:
        return redirect('/')
    reviews = Review.objects.filter(for_book=book).all()
    return render(request, 'details.html', {'book': book, 'reviews': reviews})


@siteuser_basic_auth(required_role="admin", realm="Admin Area")
def admin(request):
    return HttpResponse('SK-CERT{test_flag}')