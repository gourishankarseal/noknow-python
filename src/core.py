"""
src/core.py: Provides the interface for using Zero-Knowledge Proofs within applications
"""

from base64 import b64encode, b64decode
from ecpy.curves import Curve, Point
from noknow.utils.convert import to_bytes, to_str, bytes_to_int, unpack
from noknow.utils.crypto import hash_numeric
from random import SystemRandom
from typing import NamedTuple, Union
import json

random = SystemRandom()


__all__ = [
    "ZKParameters", "ZKSignature", "ZKProof", "ZKData", "ZK",
]


def _dump(obj):
    return to_str(b64encode(to_bytes(json.dumps(unpack(obj), separators=(",", ":")))))


class ZKParameters(NamedTuple):
    """
    Parameters used to construct a ZK proof state using an curve and a random salt
    """
    alg: str                    # Hashing algorithm name
    curve: str                  # Standard Elliptic Curve name to use
    s: int                      # Random salt for the state

    @staticmethod
    def load(data):
        return ZKParameters(**json.loads(to_str(b64decode(to_bytes(data)))))
    dump = _dump


class ZKSignature(NamedTuple):
    """
    Cryptographic public signature used to verify future messages
    """
    params: ZKParameters        # Reference ZK Parameters
    signature: int              # The public key derived from your original secret

    @staticmethod
    def load(data):
        info = json.loads(to_str(b64decode(to_bytes(data))))
        return ZKSignature(params=ZKParameters(**info.pop("params")), **info)
    dump = _dump


class ZKProof(NamedTuple):
    """
    Cryptographic proof that can be verified to ensure the private key used to create
    the proof is the same key used to generate the signature
    """
    params: ZKParameters        # Reference ZK Parameters
    c: int                      # The hash of the signed data and random point, R
    m: int                      # The offset from the secret `r` (`R=r*g`) from c * Hash(secret)

    @staticmethod
    def load(data):
        info = json.loads(to_str(b64decode(to_bytes(data))))
        return ZKProof(params=ZKParameters(**info.pop("params")), **info)

    dump = _dump


class ZKData(NamedTuple):
    """
    Wrapper to contain data and a signed proof using the data
    """
    data: str
    proof: ZKProof

    @staticmethod
    def load(data, separator="\n"):
        data, proof = data.rsplit(separator, 1)
        return ZKData(data=data, proof=ZKProof.load(proof))

    def dump(self, separator="\n"):
        return self.data + separator + self.proof.dump()


class ZK:
    """
    Implementation of Schnorr's protocol to create and validate proofs
    """
    def __init__(self, parameters: ZKParameters):
        """
        Initialize the curve with the given parameters
        """
        self._curve = Curve.get_curve(parameters.curve)
        if not self._curve:
            raise ValueError("The curve '{}' is invalid".format(parameters.curve))
        self._params = parameters
        self._bits = self._curve.field.bit_length()
        self._mask = (1 << self._bits) - 1

    @property
    def params(self):
        return self._params

    @property
    def bits(self):
        return self._bits

    @property
    def mask(self):
        return self._mask

    @property
    def salt(self):
        return self._params.s

    @salt.setter
    def salt(self, value):
        self._params.s = value

    @property
    def curve(self):
        return self._curve

    @staticmethod
    def new(curve_name: str = "secp256k1", hash_alg: str = "sha256", bits: int =  None):
        curve = Curve.get_curve(curve_name)
        if curve is None:
            raise ValueError("Invalid Curve")
        return ZK(ZKParameters(alg=hash_alg, curve=curve_name, s=random.getrandbits(bits or curve.field.bit_length())))

    def _to_point(self, value: Union[int, bytes, ZKSignature]):
        return self.curve.decode_point(to_bytes(value.signature if isinstance(value, ZKSignature) else value))

    def token(self) -> int:
        return random.getrandbits(self.bits)

    def hash(self, *values):
        return hash_numeric(*[v for v in values if v is not None], self.salt, alg=self.params.alg) & self._mask

    def create_signature(self, secret: Union[str, bytes]) -> ZKSignature:
        return ZKSignature(
            params=self.params,
            signature=bytes_to_int(self.hash(secret) * self.curve.generator),
        )

    def create_server_token(self, secret: Union[str, bytes], data: Union[int, str, bytes]=None) -> ZKProof:
        key = self.hash(secret)                 # Create private signing key
        r = random.getrandbits(self.bits)       # Generate random bits
        R = r * self.curve.generator            # Random point whose discrete log, `r`, is know
        c = self.hash(data, R)                  # Hash the data and random point
        m = r + c * (key % self.curve.field)    # Send offset between discrete log of R from c*x
        return ZKProof(params=self.params, c=c, m=m)

    def create_client_proof(self, secret, data) -> ZKProof:
        ## secret = ref_code,ce_code
        ref_code = secret.split(',')[-2]
        ce_code = str(secret.split(',')[-1])

        key = self.hash(ce_code)
        c = self.hash(data) # data is server generated token c
        m = self.hash(ref_code) + c * (key % self.curve.field)
        print('---------- Completed CLIENT proof-----------')
        return ZKProof(params=self.params, c=c, m=m)

#########################################################################
    def create_server_hash(self, server_signature: ZKSignature, client_signature: ZKSignature):
        sig_server = server_signature.signature
        cl_sig = client_signature.signature
        return hash_numeric(self.curve.generator, sig_server, cl_sig)

    def create_server_proof(self, proof, token, server_signature, client_signature):
        m = proof.m
        c = token  # proof.c
        s_signature = server_signature.signature
        c_signature = client_signature.signature
        calc = self.hash('', (m * self.curve.generator) - (self._to_point(s_signature) * c))

        return c_signature == calc

#########################################################################
    def sign(self, secret: Union[str, bytes],
             data: Union[int, str, bytes], signed_by = 'server') -> ZKData:
        data = to_str(data)
        if signed_by == 'server':
            return ZKData(
                data=data,
                proof=self.create_server_token(secret, data),
            )
        else:
            return ZKData(
                data=data,
                proof=self.create_client_proof(secret, data),
            )


    def verify(self, challenge: Union[ZKData, ZKProof],
               signature: ZKSignature=None,
               data: Union[str, bytes, int]=""):

        sig = signature.signature
        if isinstance(challenge, ZKProof):
            print('Instance 1')
            data, proof = data, challenge
            c, m = proof.c, proof.m
        else:
            print('Instance 2')
            data, proof = challenge.data, challenge.proof
            c, m = proof.c, proof.m
        # return sig == self.hash(data, (m * self.curve.generator) - (self._to_point(signature) * c))
        validation = c == self.hash(data, (m * self.curve.generator) - (self._to_point(signature) * c))
        return validation


