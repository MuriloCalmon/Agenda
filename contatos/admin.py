from django.contrib import admin
from . models import Categoria, Contato

class ContatoAdmin(admin.ModelAdmin):
    list_display =('id', 'nome', 'sobrenome', 'data_criacao', 'telefone', 
                   'email', 'categoria', 'mostrar')
    list_display_links = ('nome',)
    #list_filter = ('nome', 'categoria')
    list_per_page = 10
    search_fields = ('nome',)
    list_editable = ('telefone', 'mostrar')

admin.site.register(Categoria)
admin.site.register(Contato, ContatoAdmin)
