# RSACripter
# RSA Password Manager

Um sistema profissional de gerenciamento de senhas orientado a objetos que utiliza criptografia RSA para proteger credenciais de usuários através de uma arquitetura hierárquica e modular.

## 📋 Índice

- [Visão Geral](#visão-geral)
- [Arquitetura](#arquitetura)
- [Instalação](#instalação)
- [Guia de Uso](#guia-de-uso)
- [API Reference](#api-reference)
- [Exemplos Práticos](#exemplos-práticos)
- [Estrutura de Arquivos](#estrutura-de-arquivos)
- [Segurança](#segurança)
- [Testes](#testes)
- [Contribuição](#contribuição)

## 🎯 Visão Geral

O **RSA Password Manager** é uma solução completa para gerenciamento seguro de senhas que implementa:

- **Arquitetura Modular**: Classes especializadas para cada funcionalidade
- **Criptografia RSA Dupla Camada**: Chaves mestras + chaves individuais por usuário
- **Gerenciamento Automatizado**: Criação, armazenamento e recuperação automática de chaves
- **Interface Intuitiva**: API orientada a objetos fácil de usar e integrar
- **Testes Integrados**: Sistema de verificação de integridade automático

### Características Principais

✅ **RSA 4096 bits** por padrão (configurável)  
✅ **Orientação a Objetos** com separação de responsabilidades  
✅ **Type Hints** completos para melhor desenvolvimento  
✅ **Gerenciamento Automático** de arquivos e diretórios  
✅ **Testes de Integridade** integrados  
✅ **Recuperação Segura** de credenciais  
✅ **Suporte a Lotes** para múltiplos usuários  
✅ **Interface Limpa** e documentação completa  

## 🏗️ Arquitetura

O sistema é composto por 4 classes principais:

### 📦 Classes do Sistema

```python
RSAKeyManager          # Gerencia chaves mestras RSA
PasswordCrypto         # Criptografia/descriptografia de senhas
UserKeyGenerator       # Gera e gerencia chaves de usuários
RSAPasswordManager     # Classe principal que orquestra o sistema
```

### 🔄 Fluxo de Dados

```
[Usuario] → [RSAPasswordManager]
    ↓
[PasswordCrypto] → [Senha Criptografada] → [JSON]
    ↓
[UserKeyGenerator] → [Chaves RSA do Usuario] → [PEM Files]
    ↓
[RSAKeyManager] → [Chaves Mestras] → [Master PEM Files]
```

### 🔐 Segurança em Camadas

**Camada 1: Chaves Mestras**
- Criptografam/descriptografam senhas dos usuários
- Armazenadas como `chave_mestre_*.pem`

**Camada 2: Chaves de Usuário**
- Protegidas pelas senhas originais dos usuários
- Uma chave RSA única por usuário
- Usadas para operações específicas (assinatura, etc.)

## 🚀 Instalação

### Pré-requisitos

```bash
pip install cryptography typing
```

### Configuração

```bash
git clone <seu-repositorio>
cd rsa-password-manager
```

## 💻 Guia de Uso

### 🎬 Uso Básico

```python
from rsa_password_manager import RSAPasswordManager

# 1. Inicializar sistema
pm = RSAPasswordManager(master_key_size=4096, user_key_size=4096)
pm.setup_system()

# 2. Definir usuários
usuarios = [
    {'nome': 'alice', 'senha': 'senha123'},
    {'nome': 'bob', 'senha': 'minhasenha456'}
]

# 3. Criar usuários em lote
diretorio = pm.create_users_batch(usuarios)

# 4. Recuperar senha de usuário
senha_alice = pm.recover_user_password('alice')

# 5. Carregar chave privada do usuário
chave_alice = pm.load_user_key('alice')
```

### ⚙️ Configuração Avançada

```python
# Sistema com chaves menores para desenvolvimento
pm_dev = RSAPasswordManager(master_key_size=2048, user_key_size=2048)

# Sistema ultra-seguro para produção
pm_prod = RSAPasswordManager(master_key_size=8192, user_key_size=4096)
```

## 📚 API Reference

### 🔑 RSAPasswordManager

**Classe principal do sistema**

#### `__init__(master_key_size=4096, user_key_size=4096)`
Inicializa o gerenciador de senhas.

#### `setup_system() -> None`
Configura o sistema carregando ou gerando chaves mestras.

#### `create_users_batch(users_config: List[Dict]) -> str`
Cria múltiplos usuários em lote.
- **users_config**: `[{'nome': 'user', 'senha': 'pass'}, ...]`
- **Returns**: Diretório onde as chaves foram salvas

#### `recover_user_password(username: str, keys_directory=None) -> str`
Recupera a senha descriptografada de um usuário.

#### `load_user_key(username: str, keys_directory=None) -> RSAPrivateKey`
Carrega a chave privada de um usuário.

#### `test_user_system(username: str, keys_directory=None) -> bool`
Testa o sistema completo para um usuário.

#### `list_users(keys_directory=None) -> List[str]`
Lista todos os usuários disponíveis.

#### `get_system_info() -> Dict`
Retorna informações detalhadas do sistema.

### 🏭 RSAKeyManager

**Gerencia chaves mestras**

```python
km = RSAKeyManager(key_size=4096)
private_key, public_key = km.load_master_keys()
```

### 🔐 PasswordCrypto

**Criptografia de senhas**

```python
pc = PasswordCrypto(key_manager)
encrypted = pc.encrypt_password("minha_senha")
decrypted = pc.decrypt_password(encrypted)
```

### 👤 UserKeyGenerator

**Gera chaves de usuários**

```python
ukg = UserKeyGenerator(key_size=4096)
private_key, public_key = ukg.generate_user_key_pair("senha")
```

## 🛠️ Exemplos Práticos

### 📝 Exemplo Completo

```python
#!/usr/bin/env python3
from rsa_password_manager import RSAPasswordManager

def main():
    # Configurar usuários
    usuarios = [
        {'nome': 'admin', 'senha': 'admin_super_secret_2024'},
        {'nome': 'api_service', 'senha': 'service_key_production'},
        {'nome': 'backup_user', 'senha': 'backup_secure_password'},
        {'nome': 'monitoring', 'senha': 'monitor_system_access'}
    ]
    
    print("🔐 RSA Password Manager - Sistema Empresarial")
    print("=" * 50)
    
    # 1. Inicializar sistema
    pm = RSAPasswordManager(master_key_size=4096, user_key_size=4096)
    pm.setup_system()
    
    # 2. Criar usuários
    print(f"\n📁 Criando {len(usuarios)} usuários...")
    diretorio = pm.create_users_batch(usuarios)
    
    # 3. Verificar sistema
    print(f"\n📊 Informações do Sistema:")
    info = pm.get_system_info()
    for key, value in info.items():
        print(f"  {key}: {value}")
    
    # 4. Listar usuários
    users_list = pm.list_users()
    print(f"\n👥 Usuários cadastrados:")
    for user in users_list:
        print(f"  - {user}")
    
    # 5. Testes de integridade
    print(f"\n🧪 Executando testes de integridade...")
    for user in users_list:
        success = pm.test_user_system(user)
        status = "✅ OK" if success else "❌ ERRO"
        print(f"  {user}: {status}")
    
    # 6. Demonstração de uso
    print(f"\n💡 Demonstração de recuperação:")
    try:
        senha_admin = pm.recover_user_password('admin')
        print(f"  Senha do admin recuperada: {senha_admin}")
        
        chave_admin = pm.load_user_key('admin')
        print(f"  Chave privada do admin carregada: {type(chave_admin).__name__}")
        
    except Exception as e:
        print(f"  Erro: {e}")
    
    print(f"\n✅ Sistema configurado com sucesso!")
    print(f"📁 Localização: {diretorio}")

if __name__ == "__main__":
    main()
```

### 🔌 Integração com Sistema Existente

```python
class AuthenticationService:
    """Serviço de autenticação usando RSA Password Manager"""
    
    def __init__(self, keys_directory: str):
        self.pm = RSAPasswordManager()
        self.pm.setup_system()
        self.keys_dir = keys_directory
    
    def authenticate_user(self, username: str) -> bool:
        """Autentica usuário recuperando sua senha"""
        try:
            # Recuperar senha criptografada
            password = self.pm.recover_user_password(username, self.keys_dir)
            
            # Validar contra sistema externo
            return self.validate_external_auth(username, password)
            
        except Exception as e:
            print(f"Falha na autenticação de {username}: {e}")
            return False
    
    def get_user_signing_key(self, username: str):
        """Obtém chave de assinatura do usuário"""
        try:
            return self.pm.load_user_key(username, self.keys_dir)
        except Exception as e:
            print(f"Erro ao carregar chave de {username}: {e}")
            return None
    
    def validate_external_auth(self, username: str, password: str) -> bool:
        # Implementar validação com sistema externo
        return True  # Placeholder

# Uso do serviço
auth_service = AuthenticationService("usuarios_chaves_20241201_143022")

if auth_service.authenticate_user("admin"):
    signing_key = auth_service.get_user_signing_key("admin")
    print("Usuário autenticado e chave obtida!")
```

### 🔄 Sistema de Rotação de Chaves

```python
class KeyRotationManager:
    """Gerencia rotação periódica de chaves"""
    
    def __init__(self):
        self.pm = RSAPasswordManager()
    
    def rotate_user_keys(self, username: str, old_keys_dir: str) -> str:
        """Rotaciona chaves de um usuário específico"""
        try:
            # 1. Recuperar senha atual
            current_password = self.pm.recover_user_password(username, old_keys_dir)
            
            # 2. Criar novo sistema
            new_config = [{'nome': username, 'senha': current_password}]
            new_keys_dir = self.pm.create_users_batch(new_config)
            
            # 3. Testar novo sistema
            if self.pm.test_user_system(username, new_keys_dir):
                print(f"✅ Chaves de {username} rotacionadas com sucesso")
                return new_keys_dir
            else:
                raise Exception("Falha na validação das novas chaves")
                
        except Exception as e:
            print(f"❌ Erro na rotação de chaves para {username}: {e}")
            raise

# Uso
rotation_manager = KeyRotationManager()
new_dir = rotation_manager.rotate_user_keys("admin", "usuarios_chaves_old")
```

## 📁 Estrutura de Arquivos

```
projeto/
├── rsa_password_manager.py          # Código principal
├── chave_mestre_private.pem         # Chave privada mestra
├── chave_mestre_public.pem          # Chave pública mestra
├── usuarios_chaves_20241201_143022/ # Diretório timestampado
│   ├── senhas_criptografadas.json   # Senhas criptografadas
│   ├── alice_private.pem            # Chave privada - Alice
│   ├── alice_public.pem             # Chave pública - Alice
│   ├── bob_private.pem              # Chave privada - Bob
│   ├── bob_public.pem               # Chave pública - Bob
│   └── ...                          # Outras chaves de usuários
└── README.md                        # Este arquivo
```

### 📄 Formato do arquivo `senhas_criptografadas.json`

```json
{
    "alice": "LS0tLS1CRUdJTi...base64_encrypted_password",
    "bob": "QklOQVRFREZJTEU...base64_encrypted_password",
    "admin": "RFVNS0FMSU5FUw...base64_encrypted_password"
}
```

## 🛡️ Segurança

### 🔒 Pontos Fortes

- **RSA 4096 bits**: Padrão militar de segurança
- **OAEP Padding**: Proteção contra ataques oracle
- **SHA-256 Hashing**: Algoritmo criptográfico moderno
- **Separação de Chaves**: Chaves mestras isoladas das individuais
- **Proteção Dupla**: Cada usuário tem proteção independente
- **Sem Plaintext**: Nenhuma senha armazenada em texto claro

### ⚠️ Considerações Importantes

**Para Ambiente de Produção:**

1. **Proteger Chave Mestra**:
```python
# Exemplo de chave mestra protegida
encryption_algorithm=serialization.BestAvailableEncryption(b"master_password_ultra_forte")
```

2. **Backup Seguro**:
```python
import shutil
import os

def backup_keys(source_dir: str, backup_location: str):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = f"{backup_location}/backup_{timestamp}"
    shutil.copytree(source_dir, backup_dir)
    # Criptografar backup adicional aqui
```

3. **Controle de Acesso**:
```bash
# Definir permissões restritivas
chmod 600 chave_mestre_*.pem
chmod 700 usuarios_chaves_*/
```

4. **Auditoria**:
```python
import logging

logging.basicConfig(
    filename='rsa_password_manager.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_access(username: str, operation: str):
    logging.info(f"User: {username}, Operation: {operation}")
```

### 🔐 Matriz de Segurança

| Componente | Algoritmo | Tamanho | Proteção |
|------------|-----------|---------|-----------|
| Chave Mestra | RSA | 4096 bits | OAEP + SHA-256 |
| Chave Usuário | RSA | 4096 bits | Password + PKCS8 |
| Hash | SHA-256 | 256 bits | Cryptographic |
| Padding | OAEP | - | Oracle-resistant |

## 🧪 Testes

### 🔍 Testes Integrados

O sistema inclui testes automáticos de integridade:

```python
# Teste individual
pm = RSAPasswordManager()
pm.setup_system()
success = pm.test_user_system('username')

# Teste em lote
for user in pm.list_users():
    result = pm.test_user_system(user)
    print(f"{user}: {'✅ OK' if result else '❌ ERRO'}")
```

### 🧪 Testes Personalizados

```python
def test_encryption_decryption():
    """Testa ciclo completo de criptografia"""
    pm = RSAPasswordManager()
    pm.setup_system()
    
    # Criar usuário teste
    test_config = [{'nome': 'test_user', 'senha': 'test_password_123'}]
    keys_dir = pm.create_users_batch(test_config)
    
    # Verificar recuperação
    recovered = pm.recover_user_password('test_user')
    assert recovered == 'test_password_123'
    
    # Verificar carregamento de chave
    private_key = pm.load_user_key('test_user')
    assert private_key is not None
    
    print("✅ Todos os testes passaram!")

def test_performance():
    """Testa performance do sistema"""
    import time
    
    start_time = time.time()
    
    # Criar múltiplos usuários
    users = [{'nome': f'user_{i}', 'senha': f'password_{i}'} 
             for i in range(10)]
    
    pm = RSAPasswordManager()
    pm.setup_system()
    keys_dir = pm.create_users_batch(users)
    
    end_time = time.time()
    print(f"⏱️ Criação de 10 usuários: {end_time - start_time:.2f}s")

# Executar testes
test_encryption_decryption()
test_performance()
```

## 📊 Monitoramento

### 📈 Métricas do Sistema

```python
def get_system_metrics(keys_directory: str) -> dict:
    """Coleta métricas do sistema"""
    pm = RSAPasswordManager()
    
    users = pm.list_users(keys_directory)
    
    metrics = {
        'total_users': len(users),
        'master_key_exists': os.path.exists('chave_mestre_private.pem'),
        'directory_size': get_directory_size(keys_directory),
        'last_access': get_last_access_time(keys_directory)
    }
    
    return metrics

def get_directory_size(directory: str) -> int:
    """Calcula tamanho do diretório em bytes"""
    total = 0
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            total += os.path.getsize(filepath)
    return total
```

## 🤝 Contribuição

### 📋 Como Contribuir

1. **Fork** o repositório
2. **Clone** seu fork: `git clone <seu-fork>`
3. **Crie** uma branch: `git checkout -b feature/nova-funcionalidade`
4. **Implemente** suas mudanças
5. **Teste** thoroughly: Execute todos os testes
6. **Commit**: `git commit -m 'Add: nova funcionalidade'`
7. **Push**: `git push origin feature/nova-funcionalidade`
8. **Pull Request**: Abra um PR detalhado

### 🎯 Guidelines de Desenvolvimento

- **Type Hints**: Use tipagem completa em todas as funções
- **Docstrings**: Documente métodos públicos
- **Error Handling**: Trate exceções adequadamente
- **Code Style**: Siga PEP 8
- **Testes**: Inclua testes para novas funcionalidades
- **Segurança**: Considere implicações de segurança

### 🐛 Report de Bugs

Ao reportar bugs, inclua:

- **Sistema Operacional**
- **Versão do Python**
- **Versão da biblioteca `cryptography`**
- **Código que reproduz o erro**
- **Stacktrace completo**
- **Comportamento esperado vs observado**

## 🆘 Suporte
- 📖 **Documentação**: [cryptography.io](https://cryptography.io/en/latest/)

## 🏆 Reconhecimentos

- **cryptography**: Biblioteca principal para operações criptográficas
- **Python Software Foundation**: Pela linguagem Python
- **OpenSSL**: Backend criptográfico

---

**⚠️ Aviso Legal**: Este software é fornecido para fins educacionais e de desenvolvimento. Para uso em produção, implemente medidas de segurança adicionais e consulte especialistas em cibersegurança.

**🔒 Nota de Segurança**: As chaves mestras são críticas para a segurança do sistema. Mantenha-as seguras e faça backups regulares.
