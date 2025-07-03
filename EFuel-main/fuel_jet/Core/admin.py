from django.contrib import admin
from .models import PasswordReset,Inventory,Order,PetrolPump

admin.site.register(PasswordReset)
admin.site.register(Inventory)
class OrderAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'latitude', 'longitude', 'phone', 'status', 'ordered_at')

admin.site.register(Order, OrderAdmin)
admin.site.register(PetrolPump)