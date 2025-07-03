from django.db import models
from django.contrib.auth.models import User
import uuid

class PasswordReset(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    reset_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_when = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Password reset for {self.user.username} at {self.created_when}"

class Inventory(models.Model):
    fuel_type = models.CharField(max_length=100)
    quantity = models.FloatField(default=0)  # or FloatField for liters/gallons

    def __str__(self):
        return f"{self.fuel_type} ({self.quantity} L)"

class PetrolPump(models.Model):
    name = models.CharField(max_length=100)

class Order(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('paid', 'Paid'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='orders')
    phone = models.CharField(max_length=15, null=True, blank=True)  # User's phone number
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    selected_pump = models.CharField(max_length=100)  # Petrol pump name as text
    fuel_type = models.CharField(max_length=100)
    quantity = models.FloatField(help_text="Quantity in litres")
    price_per_litre = models.DecimalField(max_digits=10, decimal_places=2)
    total_price = models.DecimalField(max_digits=12, decimal_places=2)
    ordered_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    status_updated_at = models.DateTimeField(auto_now=True)
    user_notification = models.CharField(max_length=255, blank=True, null=True)
    admin_notification = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.fuel_type} - {self.quantity} L @ {self.ordered_at.strftime('%Y-%m-%d %H:%M')}"
class Payment(models.Model):
    customer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments')
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='payments', null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    method = models.CharField(max_length=20)
    date = models.DateTimeField(auto_now_add=True) 
class Agent(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    petrol_pump = models.ForeignKey(PetrolPump, on_delete=models.CASCADE)