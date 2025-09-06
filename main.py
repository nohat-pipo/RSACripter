from RSACripter import *
# --- Exemplo de uso ---
if __name__ == "__main__":
    # Configuração dos usuários
    usuarios_config = [
        {'nome': 'alice', 'senha': 'senha_super_secreta_alice_2024'},
        {'nome': 'bob', 'senha': 'bob_password_ultra_forte_123'},
        {'nome': 'charlie', 'senha': 'charlie_chave_privada_segura'},
        {'nome': 'admin', 'senha': 'admin_sistema_master_key_rsa'},
        {'nome': 'servidor', 'senha': 'servidor_prod_chave_4096_bits'}
    ]

    # Inicializar sistema
    password_manager = RSAPasswordManager(
        master_key_size=4096,
        user_key_size=4096
    )

    # Configurar sistema
    password_manager.setup_system()

    # Criar usuários
    diretorio_chaves = password_manager.create_users_batch(usuarios_config)

    # Mostrar informações do sistema
    print(f"\n=== INFORMAÇÕES DO SISTEMA ===")
    info = password_manager.get_system_info()
    for key, value in info.items():
        print(f"{key}: {value}")

    # Listar usuários
    users = password_manager.list_users()
    print(f"\n=== USUÁRIOS CRIADOS ===")
    for user in users:
        print(f"- {user}")

    # Testar alguns usuários
    print(f"\n=== EXECUTANDO TESTES ===")
    usuarios_teste = ['alice', 'bob', 'admin']

    for usuario in usuarios_teste:
        sucesso = password_manager.test_user_system(usuario)
        if sucesso:
            print(f"✅ {usuario}: Todos os testes passaram!")
        else:
            print(f"❌ {usuario}: Falhas nos testes!")

    print(f"\n=== RESUMO FINAL ===")
    print(f"📁 Diretório: {diretorio_chaves}")
    print(f"🔐 Usuários: {len(users)}")
    print(f"🔑 Chaves mestras: chave_mestre_*.pem")

    print(f"\n💡 Exemplo de uso programático:")
    print(f"# Recuperar senha de um usuário")
    print(f"senha = password_manager.recover_user_password('alice')")
    print(f"# Carregar chave privada do usuário")
    print(f"chave = password_manager.load_user_key('alice')")
