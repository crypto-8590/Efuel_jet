from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone
from django.urls import reverse
from .models import *

def home(request):
    return render(request, 'home.html')

def RegisterView(request):
    if request.method == "POST":
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        user_data_has_error = False

        if User.objects.filter(username=username).exists():
            user_data_has_error = True
            messages.error(request, "Username already exists")

        if User.objects.filter(email=email).exists():
            user_data_has_error = True
            messages.error(request, "Email already exists")

        if len(password) < 5:
            user_data_has_error = True
            messages.error(request, "Password must be at least 5 characters")

        if user_data_has_error:
            return redirect('register')
        else:
            new_user = User.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                email=email, 
                username=username,
                password=password
            )
            messages.success(request, "Account created. Login now")
            return redirect('login')

    return render(request, 'register.html')

def LoginView(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user is not None and not user.is_staff:
            login(request, user)
            messages.success(request, "Login successful!")
            return redirect('index')
        else:
            messages.error(request, "Invalid login credentials")
            return redirect('login')
    return render(request, 'login.html')

def LogoutView(request):
    logout(request)
    return redirect('home')

def ForgotPassword(request):
    if request.method == "POST":
        email = request.POST.get('email', '').strip().lower()
        users = User.objects.filter(email=email)
        if not users.exists():
            messages.error(request, f"No user with email '{email}' found")
            return redirect('forgot-password')
        if users.count() > 1:
            messages.error(request, "Multiple accounts found with this email. Please contact support.")
            return redirect('forgot-password')
        user = users.first()

        new_password_reset = PasswordReset(user=user)
        new_password_reset.save()

        password_reset_url = reverse('reset-password', kwargs={'reset_id': new_password_reset.reset_id})
        full_password_reset_url = f"http://192.168.1.8:8000{password_reset_url}"

        email_body = f'Reset your password using the link below:\n\n\n{full_password_reset_url}'
        email_message = EmailMessage(
            'Reset your password',
            email_body,
            settings.EMAIL_HOST_USER,
            [email]
        )

        email_message.fail_silently = False
        email_message.send()

        return redirect('password-reset-sent', reset_id=new_password_reset.reset_id)

    return render(request, 'forgot_password.html')

def PasswordResetSent(request, reset_id):
    if PasswordReset.objects.filter(reset_id=reset_id).exists():
        return render(request, 'password_reset_sent.html')
    else:
        messages.error(request, 'Invalid reset id')
        return redirect('forgot-password')

def ResetPassword(request, reset_id):
    try:
        password_reset_id = PasswordReset.objects.get(reset_id=reset_id)

        if request.method == "POST":
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            passwords_have_error = False

            if password != confirm_password:
                passwords_have_error = True
                messages.error(request, 'Passwords do not match')

            if len(password) < 5:
                passwords_have_error = True
                messages.error(request, 'Password must be at least 5 characters long')

            expiration_time = password_reset_id.created_when + timezone.timedelta(minutes=10)

            if timezone.now() > expiration_time:
                passwords_have_error = True
                messages.error(request, 'Reset link has expired')
                password_reset_id.delete()

            if not passwords_have_error:
                user = password_reset_id.user
                user.set_password(password)
                user.save()
                password_reset_id.delete()
                messages.success(request, 'Password reset. Proceed to login')
                return redirect('login')
            else:
                return redirect('reset-password', reset_id=reset_id)

    except PasswordReset.DoesNotExist:
        messages.error(request, 'Invalid reset id')
        return redirect('forgot-password')

    return render(request, 'reset_password.html')

def about(request):
    return render(request, 'about.html')

def services(request):
    return render(request, 'services.html')

def IndexView(request):
    return render(request, 'index.html')

def contact(request):
    sent = False
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        message = request.POST.get('message')
        full_message = f"From: {name} <{email}>\n\n{message}"
        email_message = EmailMessage(
            subject=f"Contact Form Submission from {name}",
            body=full_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[settings.DEFAULT_FROM_EMAIL],
        )
        email_message.send()
        sent = True
    return render(request, 'contact.html', {'sent': sent})

def AdminLoginView(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user is not None and user.is_staff:
            login(request, user)
            messages.success(request, "Admin login successful!")
            return redirect('admin_dashboard')
        else:
            messages.error(request, "Invalid login credentials or not an admin")
            return redirect('admin-login')
    return render(request, 'admin_login.html')

def AdminRegisterView(request):
    if User.objects.filter(is_staff=True).exists():
        messages.error(request, "An admin account already exists.")
        return redirect('admin-login')

    if request.method == "POST":
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        username = request.POST.get('username')
        password = request.POST.get('password')
        User.objects.create_user(
            first_name=first_name,
            last_name=last_name,
            email=email,
            username=username,
            password=password,
            is_staff=True
        )
        messages.success(request, "Admin account created. Please log in.")
        return redirect('admin-login')
    return render(request, 'admin_register.html')

def AdminForgotPasswordView(request):
    if request.method == "POST":
        email = request.POST.get('email')
        try:
            admin_user = User.objects.get(email=email, is_staff=True)
            reset_entry = PasswordReset.objects.create(user=admin_user)
            reset_url = reverse('admin-reset-password', kwargs={'reset_id': reset_entry.reset_id})
            full_reset_url = f"http://192.168.1.8:8000{reset_url}"
            email_body = f"Click the link below to reset your admin password:\n\n{full_reset_url}"
            email_message = EmailMessage(
                "Admin Password Reset",
                email_body,
                settings.EMAIL_HOST_USER,
                [email]
            )
            email_message.send()
            return redirect('admin-password-reset-sent', reset_id=reset_entry.reset_id)
        except User.DoesNotExist:
            messages.error(request, "No admin account found with this email.")
            return redirect('admin-forgot-password')
    return render(request, 'admin_forgot_password.html')

def AdminPasswordResetSent(request, reset_id):
    if PasswordReset.objects.filter(reset_id=reset_id).exists():
        return render(request, 'admin_password_reset.html')
    else:
        messages.error(request, 'Invalid reset id')
        return redirect('admin-forgot-password')

def AdminResetPassword(request, reset_id):
    try:
        password_reset_id = PasswordReset.objects.get(reset_id=reset_id)
    except PasswordReset.DoesNotExist:
        messages.error(request, 'Invalid or expired reset link')
        return redirect('admin-forgot-password')

    passwords_have_error = False

    if request.method == "POST":
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password != confirm_password:
            passwords_have_error = True
            messages.error(request, 'Passwords do not match')

        if len(password) < 5:
            passwords_have_error = True
            messages.error(request, 'Password must be at least 5 characters long')

        expiration_time = password_reset_id.created_when + timezone.timedelta(minutes=10)
        if timezone.now() > expiration_time:
            passwords_have_error = True
            messages.error(request, 'Reset link has expired')
            password_reset_id.delete()

        if not passwords_have_error:
            user = password_reset_id.user
            user.set_password(password)
            user.save()
            password_reset_id.delete()
            messages.success(request, 'Password reset. Proceed to login')
            return redirect('admin-login')

    return render(request, 'admin_reset_password_request.html')

def AdminLogoutView(request):
    logout(request)
    messages.success(request, "Admin logged out successfully.")
    return redirect('home')

@login_required
def AdminDashboardView(request):
    if not request.user.is_staff:
        return redirect('home')

    orders = Order.objects.all().order_by('-ordered_at')
    payment_transactions = Payment.objects.select_related('customer', 'order').all().order_by('-date')
    total_payments = Payment.objects.count()
    fuel_count = Inventory.objects.count()

    return render(request, 'admin_dashboard.html', {
        'orders': orders,
        'payment_transactions': payment_transactions,
        'total_payments': total_payments,
        'fuel_count': fuel_count
    })

def CustomRedirectView(request):
    if request.user.is_staff:
        return redirect('admin_dashboard')
    else:
        return redirect('index')

def DashboardView(request):
    fuel_count = Inventory.objects.count()
    total_payments = Payment.objects.count()
    return render(request, 'dashboard.html', {
        'fuel_count': fuel_count,
        'total_payments': total_payments
    })

@login_required
def InventoryView(request):
    if request.method == "POST" and 'add_pump' in request.POST:
        pump_name = request.POST.get('pump_name')
        if pump_name:
            PetrolPump.objects.create(name=pump_name)

    if request.method == "POST" and 'update_fuel' in request.POST:
        fuel_type = request.POST.get('fuel_type')
        quantity = request.POST.get('quantity')
        if fuel_type and quantity:
            inv, created = Inventory.objects.get_or_create(fuel_type=fuel_type)
            inv.quantity = quantity
            inv.save()

    inventory = Inventory.objects.all()
    petrol_pumps = PetrolPump.objects.all()
    return render(request, 'inventory.html', {
        'inventory': inventory,
        'petrol_pumps': petrol_pumps,
    })

def PaymentView(request):
    records = Payment.objects.all()
    return render(request, 'payment_transction.html', {'records': records})

@login_required
def OrderView(request):
    order_status = None
    order = None

    orders = Order.objects.filter(user=request.user, status__in=['pending', 'approved']).order_by('-ordered_at')
    if orders.exists():
        order = orders.first()
        order_status = order.status

    if request.method == "POST":
        fuel_type = request.POST.get('fuel_type')
        quantity = request.POST.get('quantity')
        price_per_litre = request.POST.get('price_per_litre')
        latitude = request.POST.get('latitude')
        longitude = request.POST.get('longitude')
        phone = request.POST.get('phone')
        selected_pump_id = request.POST.get('selected_pump')
        pump = PetrolPump.objects.get(id=selected_pump_id)
        selected_pump = pump.name.strip()

        if not quantity or not price_per_litre:
            return redirect('order')

        total_price = float(quantity) * float(price_per_litre)

        Order.objects.create(
            user=request.user,
            latitude=latitude,
            longitude=longitude,
            fuel_type=fuel_type,
            quantity=quantity,
            price_per_litre=price_per_litre,
            total_price=total_price,
            phone=phone,
            selected_pump=selected_pump,
            status='pending'
        )
        return redirect('order_pending')
    petrol_pumps = PetrolPump.objects.all()
    fuel_types = Inventory.objects.values_list('fuel_type', flat=True).distinct()
    return render(request, 'order.html', {
        'order_status': order_status,
        'order': order,
        'petrol_pumps': petrol_pumps,
        'fuel_types': fuel_types
    })

@login_required
def payment_page(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    if order.status != 'approved':
        messages.error(request, "Order not approved yet!")
        return redirect('order')
    if request.method == "POST":
        Payment.objects.create(
            customer=request.user,
            amount=order.total_price,
            order=order
        )
        order.status = 'paid'
        order.save()
        messages.success(request, "Payment successful!")
        return redirect(f"{reverse('payment_success')}?amount={order.total_price}&order_id={order.id}")
    return render(request, 'payment_page.html', {'order': order})

@login_required
def AdminApproveOrderView(request, order_id):
    if not request.user.is_staff:
        return redirect('home')
    order = get_object_or_404(Order, id=order_id)
    order.status = 'approved'
    order.save()
    messages.success(request, "Order approved!")
    return redirect('admin_dashboard')

def payment_success(request):
    amount = request.GET.get('amount')
    return render(request, 'payment_success.html', {'order_amount': amount})

def order_pending(request):
    order = (
        Order.objects.filter(user=request.user)
        .order_by('-ordered_at')
        .first()
    )
    order_status = order.status if order else None
    return render(request, 'order_pending.html', {'order_status': order_status, 'order': order})

def agent_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user and hasattr(user, 'agent'):
            login(request, user)
            return redirect('agent_dashboard')
        else:
            return render(request, 'agent_login.html', {'error': 'Invalid credentials'})
    return render(request, 'agent_login.html')
@login_required
def agent_dashboard(request):
    try:
        agent = request.user.agent
    except Agent.DoesNotExist:
        return redirect('agent_login')

    orders = Order.objects.filter(
        selected_pump__iexact=agent.petrol_pump.name.strip(),
        status__in=['paid', 'delivering']
    ).order_by('-ordered_at')
    return render(request, 'agent_dashboard.html', {'orders': orders})

@login_required
def start_delivery(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    if request.method == "POST":
        order.status = 'delivering'
        order.user_notification = "Fuel is on the way! The delivery agent will call you soon."
        order.save()
        messages.info(request, "Delivery started.")
        return redirect('agent_dashboard')
    return redirect('agent_dashboard')

@login_required
def mark_delivered(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    if request.method == "POST":
        order.status = 'delivered'
        order.admin_notification = f"Order {order.id} has been delivered by the agent."
        order.save()
        messages.success(request, "Order marked as delivered.")
        return redirect('agent_dashboard')
    return redirect('agent_dashboard')

def agent_signup(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        petrol_pump_id = request.POST.get('petrol_pump')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists")
            return redirect('agent_signup')

        petrol_pump = get_object_or_404(PetrolPump, id=petrol_pump_id)

        user = User.objects.create_user(username=username, password=password)
        Agent.objects.create(user=user, petrol_pump=petrol_pump)

        messages.success(request, "Agent account created successfully")
        return redirect('agent_login')

    petrol_pumps = PetrolPump.objects.all()
    return render(request, 'agent_signup.html', {'petrol_pumps': petrol_pumps})

def payment_transactions(request):
    records = Payment.objects.select_related('customer', 'order').all().order_by('-date')
    return render(request, 'payment_transction.html', {'records': records})