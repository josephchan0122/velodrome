from base64 import b64decode, b64encode
from datetime import datetime, timedelta
import hashlib
import pickle
from typing import Tuple
import uuid

# cryptography - uses in other requirements
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.conf import settings
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView


class TokenGenerator:
    """Key server access token generator.
    """

    max_age = 3600 * 24 * 30
    _core = uuid.UUID("6e49e4b9e8054bfdb7c28dbe5dc21f58")
    mode = None
    key = None
    error = None

    def __init__(
        self, password: str, expiration: int = 0
    ) -> None:
        """Password from settings.
        """
        self.key = hashlib.md5(password.encode()).digest()
        self.mode = modes.CFB(self._core.bytes)
        if expiration >= 1:
            self.max_age = expiration

    def create_token(self, **data) -> str:
        """Create a token with encrypted data by AES algorithms.
        """
        salt = uuid.uuid4().bytes
        cipher = Cipher(algorithms.AES(self.key + salt), self.mode)
        data_stream = pickle.dumps([
            data, datetime.now() + timedelta(seconds=self.max_age)
        ])
        encryptor = cipher.encryptor()
        hidden_data = encryptor.update(data_stream) + encryptor.finalize()
        return b64encode(salt + hidden_data).decode()

    def open_token(self, token: str) -> Tuple[dict, bool]:
        """Decryption of source object and check correction of results.
        """
        self.error = None
        correct = True
        result = {}
        try:
            token_data = b64decode(token)
            salt = token_data[:16]
            source = token_data[16:]
            cipher = Cipher(algorithms.AES(self.key + salt), self.mode)
            decryptor = cipher.decryptor()
            data, max_dt = pickle.loads(
                decryptor.update(source) + decryptor.finalize()
            )
        except pickle.UnpicklingError:
            correct = False
        except Exception as err:
            self.error = err
        else:
            correct = datetime.now() <= max_dt and isinstance(data, dict)
            if correct:
                result.update(data)

        return result, correct


class KeyServerAccessTokenView(APIView):
    """Api to create simple access tokens for api of key server.
    """

    permission_classes = [IsAuthenticated]
    generator: TokenGenerator = None

    def get(self, request, **kwargs):
        """Create a token.
        """
        answer = {}
        user = request.user if hasattr(request, "user") else None
        if user and not user.is_anonymous:
            age = settings.KEY_SERVER_API_TOKEN_MAX_AGE
            if self.generator is None:
                self.generator = TokenGenerator(
                    settings.KEY_SERVER_API_PASSWORD, expiration=age
                )

            new_status = status.HTTP_200_OK
            organizations = user.get_descendants_organizations()
            answer["max_age"] = age
            aff_set = set(
                user.affiliations.all().values_list(
                    "role", "organization__pk"
                ).iterator()
            )
            user_orgs = [
                [
                    org.name,
                    [role for role, org_pk in aff_set if org.pk == org_pk],
                ]
                for org in organizations.order_by("parent").iterator()
            ]
            answer["token"] = self.generator.create_token(
                u=user.email, uid=str(user.uuid), orgs=user_orgs
            )
        else:
            new_status = status.HTTP_403_FORBIDDEN
            answer["error"] = "No user"

        return Response(data=answer, status=new_status)
