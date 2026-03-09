from django.db import models

class SiteUser(models.Model):
    username = models.CharField(max_length=50, unique=True)
    password = models.TextField()
    ROLE_CHOICES = [
        ("customer", "Customer"),
        ("author", "Author"),
        ("admin", "Admin"),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)

class Author(models.Model):
    name = models.CharField(max_length=50, unique=True)
    bio = models.CharField(max_length=500)
    user_account = models.OneToOneField(on_delete=models.SET_NULL, null=True, to=SiteUser)

class Book(models.Model):
    author = models.ForeignKey(to=Author, on_delete=models.CASCADE, related_name='books')
    title = models.CharField(max_length=80, unique=True)
    picture = models.TextField()
    price = models.DecimalField(max_digits=5, decimal_places=2, default='20.00')
    description = models.TextField(default="It's a book... the pages are paper... and it's very booky.")
    
    
class Review(models.Model):
    text = models.TextField()
    by_user = models.ForeignKey(on_delete=models.CASCADE, to=SiteUser)
    for_book = models.ForeignKey(on_delete=models.CASCADE, to=Book, related_name='reviews')
