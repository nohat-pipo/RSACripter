# RSACripter
# Sistema de Gerenciamento Seguro de Senhas com RSA

Um sistema de gerenciamento de senhas que utiliza criptografia RSA para proteger credenciais de usuários de forma hierárquica e segura.

## 📋 Índice

- [Descrição](#descrição)
- [Características](#características)
- [Arquitetura de Segurança](#arquitetura-de-segurança)
- [Instalação](#instalação)
- [Uso](#uso)
- [Estrutura de Arquivos](#estrutura-de-arquivos)
- [Exemplos](#exemplos)
- [Segurança](#segurança)
- [Limitações](#limitações)
- [Contribuição](#contribuição)

## 📖 Descrição

Este sistema implementa uma solução de gerenciamento de senhas baseada em criptografia RSA de dupla camada:

1. **Chaves Mestras**: Par de chaves RSA usado para criptografar/descriptografar senhas dos usuários
2. **Chaves de Usuário**: Chaves RSA individuais protegidas pelas senhas originais dos usuários

O sistema permite armazenar senhas de forma criptografada e recuperá-las quando necessário, mantendo a segurança através de múltiplas camadas de proteção.

## ✨ Características

- **Criptografia RSA 4096 bits** por padrão (configurável)
- **Dupla camada de proteção**: chaves mestras + chaves individuais
- **Armazenamento seguro** de senhas criptografadas
- **Recuperação automática** de credenciais
- **Geração automática** de pares de chaves
- **Testes de integridade** incluídos
- **Organização temporal** de arquivos
- **Suporte a múltiplos usuários**

## 🔐 Arquitetura de Segurança

### Camada 1: Chaves Mestras
```
Senha do Usuário → [Chave Pública Mestra] → Senha Criptografada
Senha Criptografada → [Chave Privada Mestra] → Senha Original
```

### Camada 2: Chaves Individuais
```
Senha Original → [Proteção da Chave Privada Individual] → Chave RSA do Usuário
```

### Fluxo de Segurança
1. As senhas dos usuários são criptografadas com a chave pública mestra
2. As chaves privadas individuais são protegidas com as senhas originais
3. Para acessar recursos do usuário, é necessário:
   - Descriptografar a senha usando a chave privada mestra
   - Usar a senha descriptografada para desbloquear a chave privada individual

## 🚀 Instalação

### Pré-requisitos

```bash
pip install cryptography
```

### Instalação do Projeto

```bash
git clone <seu-repositorio>
cd sistema-gerenciamento-senhas
```

## 💻 Uso

### 1. Configuração Básica

```python
from sistema_senhas import *

# Definir usuários e senhas
usuarios = [
    {'nome': 'alice', 'senha': 'senha123'},
    {'nome': 'bob', 'senha': 'minhasenha456'},
    {'nome': 'carol', 'senha': 'senhasegura789'}
]

# Gerar sistema completo
info_usuarios, diretorio, senhas_criptografadas = gerar_chaves_usuarios_com_senhas_criptografadas(usuarios)
```

### 2. Recuperar Senha de Usuário

```python
# Recuperar senha original descriptografada
senha_alice = recuperar_senha_usuario('alice', diretorio)
print(f"Senha da Alice: {senha_alice}")
```

### 3. Testar Sistema

```python
# Testar integridade completa do sistema
testar_recuperacao_senha('alice', diretorio)
```

### 4. Uso Manual das Funções

```python
# Gerar chaves mestras manualmente
private_key, public_key = gerar_par_chaves_mestre()

# Criptografar senha específica
senha_criptografada = criptografar_senha("minhasenha", public_key)

# Descriptografar senha
senha_original = descriptografar_senha(senha_criptografada, private_key)
```

## 📁 Estrutura de Arquivos

Após a execução, o sistema cria a seguinte estrutura:

```
projeto/
├── sistema_senhas.py                 # Código principal
├── chave_mestre_private.pem         # Chave privada mestra
├── chave_mestre_public.pem          # Chave pública mestra
└── usuarios_chaves_YYYYMMDD_HHMMSS/ # Diretório timestampado
    ├── senhas_criptografadas.json   # Senhas criptografadas
    ├── alice_private.pem            # Chave privada da Alice
    ├── alice_public.pem             # Chave pública da Alice
    ├── bob_private.pem              # Chave privada do Bob
    ├── bob_public.pem               # Chave pública do Bob
    └── ...
```

### Arquivo `senhas_criptografadas.json`

```json
{
    "alice": "base64_encrypted_password_here",
    "bob": "base64_encrypted_password_here",
    "carol": "base64_encrypted_password_here"
}
```

## 🔧 Exemplos

### Exemplo Completo de Uso

```python
#!/usr/bin/env python3

from sistema_senhas import *

def main():
    # 1. Definir usuários
    usuarios = [
        {'nome': 'admin', 'senha': 'admin123!@#'},
        {'nome': 'user1', 'senha': 'password456'},
        {'nome': 'user2', 'senha': 'mypassword789'}
    ]
    
    print("=== Sistema de Gerenciamento de Senhas ===\n")
    
    # 2. Gerar sistema completo
    print("1. Gerando chaves e criptografando senhas...")
    info_usuarios, diretorio, senhas_cripto = gerar_chaves_usuarios_com_senhas_criptografadas(usuarios)
    
    # 3. Demonstrar recuperação
    print("\n2. Testando recuperação de senhas...")
    for usuario in usuarios:
        nome = usuario['nome']
        senha_original = usuario['senha']
        
        # Recuperar senha
        senha_recuperada = recuperar_senha_usuario(nome, diretorio)
        
        # Verificar se bate
        if senha_original == senha_recuperada:
            print(f"✓ {nome}: Senha recuperada com sucesso")
        else:
            print(f"✗ {nome}: ERRO na recuperação")
    
    # 4. Testes de integridade
    print("\n3. Executando testes de integridade...")
    for usuario in usuarios:
        testar_recuperacao_senha(usuario['nome'], diretorio)
    
    print(f"\n✓ Sistema configurado em: {diretorio}")

if __name__ == "__main__":
    main()
```

### Exemplo de Integração com Sistema Existente

```python
class SistemaAutenticacao:
    def __init__(self, diretorio_chaves):
        self.diretorio = diretorio_chaves
    
    def autenticar_usuario(self, nome_usuario):
        """Autentica usuário recuperando sua senha"""
        try:
            senha = recuperar_senha_usuario(nome_usuario, self.diretorio)
            return self.validar_credenciais(nome_usuario, senha)
        except Exception as e:
            print(f"Erro na autenticação: {e}")
            return False
    
    def validar_credenciais(self, usuario, senha):
        # Sua lógica de validação aqui
        return True  # Exemplo

# Uso
sistema = SistemaAutenticacao("usuarios_chaves_20241201_143022")
if sistema.autenticar_usuario("alice"):
    print("Usuário autenticado!")
```

## 🛡️ Segurança

### Pontos Fortes

- **RSA 4096 bits**: Padrão de segurança alto
- **OAEP Padding**: Proteção contra ataques de padding
- **SHA-256**: Hash criptográfico seguro
- **Dupla proteção**: Chaves mestras + individuais
- **Sem senhas em texto plano**: Tudo armazenado criptografado

### Considerações de Segurança

⚠️ **IMPORTANTE**: Este sistema é para fins educacionais e de desenvolvimento. Para uso em produção, considere:

1. **Proteção da Chave Mestra**: A chave privada mestra deve ser protegida por senha
2. **Armazenamento Seguro**: Use HSMs ou key vaults para chaves sensíveis
3. **Backup Seguro**: Implemente backup criptografado das chaves
4. **Rotação de Chaves**: Política de rotação regular
5. **Auditoria**: Log de acessos e operações
6. **Controle de Acesso**: Permissões rigorosas nos arquivos

### Recomendações de Produção

```python
# Exemplo de chave mestra protegida por senha
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b"senha_muito_forte_aqui")
)
```

## 📝 Limitações

1. **Tamanho das Senhas**: RSA tem limite de dados que pode criptografar diretamente
2. **Performance**: Operações RSA são mais lentas que criptografia simétrica
3. **Gerenciamento de Chaves**: Requer cuidado especial com a chave mestra
4. **Escalabilidade**: Para muitos usuários, considere soluções híbridas
5. **Dependência**: Perda da chave mestra = perda de todas as senhas

## 🔄 Fluxograma do Sistema

```
[Usuário] → [Senha Original]
    ↓
[Chave Pública Mestra] → [Senha Criptografada] → [JSON File]
    ↓
[Senha Original] → [Proteção da Chave Privada Individual] → [PEM File]
    ↓
[Recuperação] → [Chave Privada Mestra] → [Senha Descriptografada]
    ↓
[Senha Descriptografada] → [Desbloquear Chave Individual] → [Uso]
```

## 🤝 Contribuição

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/MinhaFeature`)
3. Commit suas mudanças (`git commit -m 'Adiciona MinhaFeature'`)
4. Push para a branch (`git push origin feature/MinhaFeature`)
5. Abra um Pull Request

## 🆘 Suporte

Para dúvidas ou problemas:

1. Abra uma issue no GitHub
2. Consulte a documentação da biblioteca `cryptography`
3. Verifique os logs de erro do sistema

---

**⚠️ Aviso Legal**: Este código é fornecido apenas para fins educacionais. Para uso em produção, implemente todas as medidas de segurança necessárias e consulte especialistas em cibersegurança.
