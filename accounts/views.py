from django.shortcuts import render, redirect
from django.contrib import messages, auth
from django.core.validators import validate_email
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from .models import ContatoForm

def login(request):
    if request.method != 'POST':
        return render(request, 'accounts/login.html')

    usuario = request.POST.get('user')
    senha = request.POST.get('senha')
    user = auth.authenticate(request, username=usuario, password=senha)

    if not user:
        messages.error(request, 'Usuário ou senha inválidos!')
        return render(request, 'accounts/login.html')
    else:
        auth.login(request, user)
        messages.success(request, 'Bem vindo!') 
        return redirect('dashboard')     

def logout(request):
    auth.logout(request)
    return redirect('login')

def register(request):
    if request.method != 'POST':
        return render(request, 'accounts/register.html')
    
    nome = request.POST.get('nome')
    sobrenome = request.POST.get('sobrenome')
    email = request.POST.get('email')
    usuario = request.POST.get('user')
    senha = request.POST.get('senha')
    confirmsenha = request.POST.get('confirmsenha')

    if not nome or not sobrenome or not email or not usuario or not \
    senha or not confirmsenha:
        messages.error(request, 'Por favor, preencha todos os campos')    
        return render(request, 'accounts/register.html')

    if not senha == confirmsenha:
        messages.error(request, 'Senhas não coincidem')
        return render(request, 'accounts/register.html')

    try:
        validate_email(email)
    except:
        messages.error(request, 'Email inváldo')
        return render(request, 'accounts/register.html')

    if len(senha) < 6:
        messages.error(request, 'Senha precisa ter 6 caracteres ou mais')
        return render(request, 'accounts/register.html')

    if len(usuario) < 4:
        messages.error(request, 'Usuário precisa ter 4 caracteres ou mais')
        return render(request, 'accounts/register.html')

    if User.objects.filter(username=usuario).exists():
        messages.error(request, 'Usuário já existe')
        return render(request, 'accounts/register.html')

    if User.objects.filter(email=email).exists():
        messages.error(request, 'email já existe')
        return render(request, 'accounts/register.html')
     
    
    messages.success(request, 'Usuário cadastrado com sucesso!')
    user = User.objects.create_user(username=usuario, email=email, 
    password=senha, first_name=nome, last_name=sobrenome)
    user.save()

    return redirect('login')
    

@login_required(redirect_field_name='login')
def dashboard(request):
    if request.method != 'POST':
        form = ContatoForm()
        return render(request, 'accounts/dashboard.html', {'form': form})
    
    form = ContatoForm(request.POST, request.FILES)
    if not form.is_valid:
        messages.error(request, 'Erro ao enviar o formuláro')
        form = ContatoForm(request.POST)
        return render(request, 'accounts/dashboard.html', {'form': form})
    
    form.save()
    messages.success(request, 'Salvo com sucesso')
    return redirect('dashboard')

