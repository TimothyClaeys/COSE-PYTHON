from enum import IntEnum
from typing import Optional, Tuple

import dataclasses
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from dataclasses import dataclass

from pycose.algorithms import AlgorithmIDs, AlgoParam, AlgID2Crypto
from pycose.context import CoseKDFContext
from pycose.exceptions import CoseInvalidAlgorithm
from pycose.keys.cosekey import CoseKey, KTY, EllipticCurveType, KeyOps


@CoseKey.record_kty(KTY.OKP)
@dataclass(init=False)
class OKP(CoseKey):
    """
    Octet Key Pairs: Do not assume that keys using this type are elliptic curves.  This key type could be used for
    other curve types.
    """
    _crv: Optional[EllipticCurveType] = None
    _x: Optional[bytes] = None
    _d: Optional[bytes] = None

    class OKPPrm(IntEnum):
        CRV = -1
        X = -2
        D = -4

    @classmethod
    def from_cose_key_obj(cls, cose_key_obj: dict) -> 'OKP':
        """ Returns an initialized COSE_Key object of type OKP."""

        cose_key = cls(
            kid=cose_key_obj.get(cls.Common.KID),
            alg=cose_key_obj.get(cls.Common.ALG),
            key_ops=cose_key_obj.get(cls.Common.KEY_OPS),
            base_iv=cose_key_obj.get(cls.Common.BASE_IV),
            crv=cose_key_obj.get(cls.OKPPrm.CRV),
            x=cose_key_obj.get(cls.OKPPrm.X),
            d=cose_key_obj.get(cls.OKPPrm.D)
        )

        return cose_key

    def __init__(self,
                 kid: Optional[bytes] = None,
                 alg: Optional[int] = None,
                 key_ops: Optional[int] = None,
                 base_iv: Optional[bytes] = None,
                 crv: Optional[int] = None,
                 x: Optional[bytes] = None,
                 d: Optional[bytes] = None):
        super().__init__(KTY.OKP, kid, alg, key_ops, base_iv)
        self.crv = crv
        self.x = x
        self.d = d

    @property
    def crv(self) -> Optional[EllipticCurveType]:
        return self._crv

    @crv.setter
    def crv(self, new_crv: Optional[EllipticCurveType]) -> None:
        if new_crv is not None:
            _ = EllipticCurveType(new_crv)
        self._crv = new_crv

    @property
    def x(self) -> Optional[bytes]:
        return self._x

    @x.setter
    def x(self, new_x: Optional[bytes]) -> None:
        if type(new_x) is not bytes and new_x is not None:
            raise ValueError("public x coordinate must be of type 'bytes'")
        self._x = new_x

    @property
    def d(self) -> Optional[bytes]:
        return self._d

    @d.setter
    def d(self, new_d: Optional[bytes]) -> None:
        if type(new_d) is not bytes and new_d is not None:
            raise ValueError("private key must be of type 'bytes'")
        self._d = new_d

    @property
    def public_bytes(self) -> Optional[bytes]:
        return self.x

    @property
    def private_bytes(self) -> Optional[bytes]:
        return self.d

    def encode(self, *argv):
        kws = []

        for kw in argv:
            if kw.upper() in self.OKPPrm.__members__:
                kws.append('_' + kw)

        return {**super().encode(*argv), **{self.OKPPrm[kw[1:].upper()]: dataclasses.asdict(self)[kw] for kw in kws}}

    def __repr__(self):
        content = self.encode()
        output = ['<COSE_Key(OKP)>']
        output.extend(self._base_repr(k, v) if k not in [-2, -4] else self._key_repr(k, v) for k, v in content.items())
        return "\n".join(output)

    def x25519_key_derivation(self,
                              public_key: 'OKP',
                              context: CoseKDFContext = b'',
                              alg: Optional[AlgorithmIDs] = None,
                              curve: Optional[EllipticCurveType] = None) -> Tuple[bytes, bytes]:

        self._check_key_conf(alg, KeyOps.DERIVE_KEY, public_key, curve)

        try:
            alg = self.alg.name if hasattr(self.alg, "name") else AlgorithmIDs(self.alg).name

            algorithm: AlgoParam = AlgID2Crypto[alg].value
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        p = X25519PublicKey.from_public_bytes(public_key.x)
        d = X25519PrivateKey.from_private_bytes(self.d)

        shared_secret = d.exchange(p)

        derived_key = algorithm.key_derivation(algorithm=algorithm.hash(),
                                               length=int(context.supp_pub_info.key_data_length / 8),
                                               salt=None,
                                               info=context.encode(),
                                               backend=default_backend()).derive(shared_secret)

        return shared_secret, derived_key
