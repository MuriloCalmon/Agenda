from django.shortcuts import render, get_object_or_404, redirect
from .models import Contato
from django.http import Http404
from django.core.paginator import Paginator
from django.db.models import Q, Value
from django.db.models.functions import Concat
from django.contrib import messages

def index(request):
 
    contatos = Contato.objects.order_by('-id').filter(
        mostrar = True
    )
    paginator = Paginator(contatos, 2) 
    page_number = request.GET.get('page')
    contatos = paginator.get_page(page_number)
    return render(request, 'contatos/index.html', {'contatos': contatos})


def ver_contato(request, id_contato):
    #contato = Contato.objects.get(id=id_contato)
    contato = get_object_or_404(Contato, id=id_contato)
    
    if not contato.mostrar:
        raise Http404()
    
    return render(request, 'contatos/ver_contato.html', {'contato': contato})


def busca(request):
    termo = request.GET.get('termo')

    if termo is None or not termo:
        messages.add_message(
            request,
            messages.ERROR,
            'Por favor preencha esse campo',
        )
        return redirect('index')

    campos = Concat('nome', Value(' '), 'sobrenome')
    contatos = Contato.objects.annotate(
        nome_completo=campos
    ).filter(
        Q(nome_completo__icontains=termo) | Q(telefone__icontains=termo)
    )

    paginator = Paginator(contatos, 2) 
    page_number = request.GET.get('page')
    contatos = paginator.get_page(page_number)
    return render(request, 'contatos/busca.html', {'contatos': contatos})