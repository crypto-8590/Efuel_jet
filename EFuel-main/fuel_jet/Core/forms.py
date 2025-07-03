from django import forms
from .models import Order

class OrderForm(forms.ModelForm):
    class Meta:
        model = Order
        fields = ['latitude', 'longitude', 'phone', 'fuel_type', 'quantity', 'selected_pump']
        widgets = {
            'latitude': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Latitude'}),
            'longitude': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Longitude'}),
            'phone': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Phone Number'}),
            'fuel_type': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Fuel Type'}),
            'quantity': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Quantity in litres', 'step': '0.01'}),
            'selected_pump': forms.Select(attrs={'class': 'form-control'}),
        }
        labels = {
            'quantity': 'Quantity (litres)',
        }