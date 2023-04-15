from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.messages import constants
from django.contrib import auth
import re

def cadastro(request):
    if request.method == "GET":
        return render(request, 'cadastro.html')
    
    elif request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        senha = request.POST.get('senha')
        confirmar_senha = request.POST.get('confirmar_senha')
        
        if len(username.strip()) == 0 or len(email.strip()) == 0 or len(senha.strip()) == 0 or len(confirmar_senha.strip()) == 0:
            messages.add_message(request, constants.WARNING, 'Por favor preencha os campos!')    
            return redirect(reverse('cadastro'))
        
        if not re.search("[@gmailoutlookkinghost.com]", email):
            messages.add_message(request, constants.WARNING, 'O domínio de e-mail digitado é inválido!')    
            return redirect(reverse('cadastro'))
            

        if not (senha == confirmar_senha):
            messages.add_message(request, constants.WARNING, 'As senhas não coêncidem!')    
            return redirect(reverse('cadastro'))
        
        if len(senha) < 6:
            messages.add_message(request, constants.WARNING, 'A senha deve possuir mas de 6 digitos!') 
            return redirect(reverse('cadastro'))
        
        if not re.search("[a-z]", senha):
            messages.add_message(request, constants.WARNING,"Sua senha deve possuir letras minusculas!")
            return redirect(reverse('cadastro'))
        
        if not re.search("[A-Z]", senha):
            messages.add_message(request, constants.WARNING,"Sua senha deve possuir letras maiusculas!")
            return redirect(reverse('cadastro'))
        
        if not re.search("[!@#$&*_]", senha):
            messages.add_message(request, constants.WARNING,"Sua senha deve possuir caracteres especiais!")
            return redirect(reverse('cadastro'))
        
        if not re.search("[0123456789]", senha):
            messages.add_message(request, constants.WARNING, "Sua senha deve possuir números!")
            return redirect(reverse('cadastro'))
        
        user = User.objects.filter(username=username)

        if user.exists():
            messages.add_message(request, constants.ERROR, 'Já existe u  usuário com esse Username!') 
            return redirect(reverse('cadastro'))   
        
        user = User.objects.create_user(username=username, email=email, password=senha)
        messages.add_message(request, constants.SUCCESS, 'Usuário cadastrado com sucesso!') 
        user.save()
        return redirect(reverse('login'))
    
def login(request):
    if request.method == "GET":
        return render(request, 'login.html')
    elif request.method == "POST":
        username = request.POST.get('username')
        senha = request.POST.get('senha')
        
        if len(username.strip()) == 0 and len(senha.strip()) == 0:
            messages.add_message(request, constants.WARNING, 'Preencha os campos corretamente')
            return redirect(reverse('login'))

        user = auth.authenticate(username=username, password=senha)

        if not user:
            messages.add_message(request, constants.ERROR, 'Username ou senha inválidos')
            return redirect(reverse('login'))
        
        auth.login(request, user)
        return redirect('/eventos/novo_evento/')
    
def sair(request):
    request.session.flush()
    messages.add_message(request, constants.INFO, 'Logout realizado com sucesso!')
    return redirect(reverse('login'))
