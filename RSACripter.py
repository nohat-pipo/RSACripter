from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import json
from datetime import datetime
from typing import Dict, List, Tuple, Optional


class RSAKeyManager:
    """Classe para gerenciar chaves RSA mestras."""

    def __init__(self, key_size: int = 4096):
        self.key_size = key_size
        self.private_key_file = "chave_mestre_private.pem"
        self.public_key_file = "chave_mestre_public.pem"
        self._private_key = None
        self._public_key = None

    def generate_master_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Gera um par de chaves RSA mestras.

        Returns:
            Tuple[RSAPrivateKey, RSAPublicKey]: Par de chaves geradas
        """
        print("Gerando chaves mestras RSA...")

        # Gerar chave privada
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )

        # Gerar chave pública
        self._public_key = self._private_key.public_key()

        # Salvar chaves
        self._save_private_key()
        self._save_public_key()

        print(f"✓ Chaves mestras geradas ({self.key_size} bits)")
        return self._private_key, self._public_key

    def _save_private_key(self) -> None:
        """Salva a chave privada em arquivo PEM."""
        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(self.private_key_file, "wb") as f:
            f.write(private_pem)

        print(f"✓ Chave privada mestra salva: {self.private_key_file}")

    def _save_public_key(self) -> None:
        """Salva a chave pública em arquivo PEM."""
        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(self.public_key_file, "wb") as f:
            f.write(public_pem)

        print(f"✓ Chave pública mestra salva: {self.public_key_file}")

    def load_master_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Carrega as chaves mestras dos arquivos.

        Returns:
            Tuple[RSAPrivateKey, RSAPublicKey]: Par de chaves carregadas
        """
        try:
            # Carregar chave privada
            with open(self.private_key_file, "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )

            # Carregar chave pública
            with open(self.public_key_file, "rb") as f:
                self._public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )

            print("✓ Chaves mestras carregadas dos arquivos")
            return self._private_key, self._public_key

        except FileNotFoundError:
            print("⚠ Chaves mestras não encontradas. Gerando novas...")
            return self.generate_master_keys()

    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        """Retorna a chave privada, carregando se necessário."""
        if self._private_key is None:
            self.load_master_keys()
        return self._private_key

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        """Retorna a chave pública, carregando se necessário."""
        if self._public_key is None:
            self.load_master_keys()
        return self._public_key


class PasswordCrypto:
    """Classe para criptografia e descriptografia de senhas."""

    def __init__(self, key_manager: RSAKeyManager):
        self.key_manager = key_manager

    def encrypt_password(self, password: str) -> str:
        """
        Criptografa uma senha usando RSA.

        Args:
            password (str): Senha em texto claro

        Returns:
            str: Senha criptografada em base64
        """
        password_bytes = password.encode('utf-8')

        encrypted = self.key_manager.public_key.encrypt(
            password_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_password(self, encrypted_password: str) -> str:
        """
        Descriptografa uma senha usando RSA.

        Args:
            encrypted_password (str): Senha criptografada em base64

        Returns:
            str: Senha descriptografada
        """
        encrypted_bytes = base64.b64decode(encrypted_password.encode('utf-8'))

        decrypted = self.key_manager.private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted.decode('utf-8')


class UserKeyGenerator:
    """Classe para gerar e gerenciar chaves RSA de usuários."""

    def __init__(self, key_size: int = 4096):
        self.key_size = key_size

    def generate_user_key_pair(self, password: str) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Gera um par de chaves RSA para um usuário.

        Args:
            password (str): Senha para proteger a chave privada

        Returns:
            Tuple[RSAPrivateKey, RSAPublicKey]: Par de chaves do usuário
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )

        public_key = private_key.public_key()
        return private_key, public_key

    def save_user_keys(self, username: str, private_key: rsa.RSAPrivateKey,
                       public_key: rsa.RSAPublicKey, password: str, directory: str) -> Dict[str, str]:
        """
        Salva as chaves de um usuário em arquivos PEM.

        Args:
            username (str): Nome do usuário
            private_key: Chave privada do usuário
            public_key: Chave pública do usuário
            password (str): Senha para proteger a chave privada
            directory (str): Diretório onde salvar as chaves

        Returns:
            Dict[str, str]: Caminhos dos arquivos salvos
        """
        private_file = os.path.join(directory, f"{username}_private.pem")
        public_file = os.path.join(directory, f"{username}_public.pem")

        # Salvar chave privada protegida por senha
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
        )

        with open(private_file, "wb") as f:
            f.write(private_pem)

        # Salvar chave pública
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(public_file, "wb") as f:
            f.write(public_pem)

        return {
            'private_file': private_file,
            'public_file': public_file
        }

    def load_user_private_key(self, username: str, password: str, directory: str) -> rsa.RSAPrivateKey:
        """
        Carrega a chave privada de um usuário.

        Args:
            username (str): Nome do usuário
            password (str): Senha da chave privada
            directory (str): Diretório das chaves

        Returns:
            RSAPrivateKey: Chave privada do usuário
        """
        private_file = os.path.join(directory, f"{username}_private.pem")

        with open(private_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode('utf-8'),
                backend=default_backend()
            )

        return private_key


class RSAPasswordManager:
    """Classe principal para gerenciar o sistema completo de senhas RSA."""

    def __init__(self, master_key_size: int = 4096, user_key_size: int = 4096):
        self.key_manager = RSAKeyManager(master_key_size)
        self.password_crypto = PasswordCrypto(self.key_manager)
        self.user_key_gen = UserKeyGenerator(user_key_size)
        self.users_info = {}
        self.encrypted_passwords = {}
        self.keys_directory = None

    def setup_system(self) -> None:
        """Inicializa o sistema carregando ou gerando chaves mestras."""
        print("=== INICIALIZANDO SISTEMA RSA PASSWORD MANAGER ===")
        self.key_manager.load_master_keys()

    def create_users_batch(self, users_config: List[Dict[str, str]]) -> str:
        """
        Cria usuários em lote com suas chaves e senhas criptografadas.

        Args:
            users_config (List[Dict]): Lista com [{'nome': 'user', 'senha': 'pass'}, ...]

        Returns:
            str: Diretório onde as chaves foram salvas
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.keys_directory = f"usuarios_chaves_{timestamp}"

        if not os.path.exists(self.keys_directory):
            os.makedirs(self.keys_directory)

        print(f"\n=== CRIANDO {len(users_config)} USUÁRIOS ===")

        for config in users_config:
            username = config['nome']
            password = config['senha']

            try:
                self._create_single_user(username, password)
                print(f"✓ Usuário {username} criado com sucesso")
            except Exception as e:
                print(f"✗ Erro ao criar usuário {username}: {e}")
                self.users_info[username] = {'error': str(e)}

        # Salvar arquivo com senhas criptografadas
        self._save_encrypted_passwords()

        return self.keys_directory

    def _create_single_user(self, username: str, password: str) -> None:
        """Cria um único usuário com chaves e senha criptografada."""
        # 1. Criptografar a senha
        encrypted_password = self.password_crypto.encrypt_password(password)
        self.encrypted_passwords[username] = encrypted_password

        # 2. Gerar chaves RSA do usuário
        private_key, public_key = self.user_key_gen.generate_user_key_pair(password)

        # 3. Salvar chaves do usuário
        files_info = self.user_key_gen.save_user_keys(
            username, private_key, public_key, password, self.keys_directory
        )

        # 4. Armazenar informações do usuário
        self.users_info[username] = {
            'private_file': files_info['private_file'],
            'public_file': files_info['public_file'],
            'encrypted_password': encrypted_password,
            'key_size': self.user_key_gen.key_size
        }

    def _save_encrypted_passwords(self) -> None:
        """Salva as senhas criptografadas em arquivo JSON."""
        passwords_file = os.path.join(self.keys_directory, "senhas_criptografadas.json")

        with open(passwords_file, "w", encoding='utf-8') as f:
            json.dump(self.encrypted_passwords, f, indent=4, ensure_ascii=False)

        print(f"✓ Senhas criptografadas salvas: {passwords_file}")

    def recover_user_password(self, username: str, keys_directory: Optional[str] = None) -> str:
        """
        Recupera e descriptografa a senha de um usuário.

        Args:
            username (str): Nome do usuário
            keys_directory (str, optional): Diretório das chaves

        Returns:
            str: Senha descriptografada
        """
        if keys_directory is None:
            keys_directory = self.keys_directory

        if keys_directory is None:
            raise ValueError("Diretório de chaves não especificado")

        passwords_file = os.path.join(keys_directory, "senhas_criptografadas.json")

        try:
            with open(passwords_file, "r", encoding='utf-8') as f:
                encrypted_passwords = json.load(f)

            if username not in encrypted_passwords:
                raise KeyError(f"Usuário {username} não encontrado")

            encrypted_password = encrypted_passwords[username]
            decrypted_password = self.password_crypto.decrypt_password(encrypted_password)

            return decrypted_password

        except Exception as e:
            raise Exception(f"Erro ao recuperar senha de {username}: {e}")

    def load_user_key(self, username: str, keys_directory: Optional[str] = None) -> rsa.RSAPrivateKey:
        """
        Carrega a chave privada de um usuário usando sua senha recuperada.

        Args:
            username (str): Nome do usuário
            keys_directory (str, optional): Diretório das chaves

        Returns:
            RSAPrivateKey: Chave privada do usuário
        """
        if keys_directory is None:
            keys_directory = self.keys_directory

        # Recuperar senha
        password = self.recover_user_password(username, keys_directory)

        # Carregar chave privada
        private_key = self.user_key_gen.load_user_private_key(username, password, keys_directory)

        return private_key

    def test_user_system(self, username: str, keys_directory: Optional[str] = None) -> bool:
        """
        Testa o sistema completo para um usuário específico.

        Args:
            username (str): Nome do usuário para testar
            keys_directory (str, optional): Diretório das chaves

        Returns:
            bool: True se todos os testes passaram
        """
        try:
            print(f"\n=== TESTANDO SISTEMA PARA: {username} ===")

            # 1. Recuperar senha
            recovered_password = self.recover_user_password(username, keys_directory)
            print(f"✓ Senha recuperada: {recovered_password}")

            # 2. Carregar chave privada
            private_key = self.load_user_key(username, keys_directory)
            public_key = private_key.public_key()
            print(f"✓ Chaves do usuário carregadas")

            # 3. Teste de assinatura
            test_message = f"Teste de assinatura para {username}".encode('utf-8')

            signature = private_key.sign(
                test_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            public_key.verify(
                signature,
                test_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            print(f"✓ Teste de assinatura/verificação passou!")
            return True

        except Exception as e:
            print(f"✗ Erro no teste para {username}: {e}")
            return False

    def list_users(self, keys_directory: Optional[str] = None) -> List[str]:
        """
        Lista todos os usuários disponíveis.

        Args:
            keys_directory (str, optional): Diretório das chaves

        Returns:
            List[str]: Lista de nomes de usuários
        """
        if keys_directory is None:
            keys_directory = self.keys_directory

        try:
            passwords_file = os.path.join(keys_directory, "senhas_criptografadas.json")
            with open(passwords_file, "r", encoding='utf-8') as f:
                encrypted_passwords = json.load(f)
            return list(encrypted_passwords.keys())
        except:
            return []

    def get_system_info(self) -> Dict:
        """Retorna informações sobre o sistema."""
        return {
            'master_key_size': self.key_manager.key_size,
            'user_key_size': self.user_key_gen.key_size,
            'keys_directory': self.keys_directory,
            'users_count': len(self.users_info),
            'users': list(self.users_info.keys())
        }


