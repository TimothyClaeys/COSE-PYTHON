from binascii import unhexlify

import pytest

from pycose import CoseMessage, Enc0Message
from pycose.attributes import CoseHeaderParam, CoseAlgorithm
from pycose.enccommon import EncCommon

message_types = [(Enc0Message, CoseMessage), (Enc0Message, EncCommon)]


@pytest.mark.parametrize("cls, parent_cls", message_types)
def test_msg_creation(cls, parent_cls):
    cose_msg = cls()

    assert isinstance(cose_msg, parent_cls)


@pytest.mark.parametrize("params, encoded_phdr",
                         [
                             ({1: 10}, b'A1010A'),
                             ({CoseHeaderParam.ALG: CoseAlgorithm.AES_CCM_16_64_128}, b'A1010A'),
                             ({1: CoseAlgorithm.AES_CCM_16_64_128}, b'A1010A'),
                             ({CoseHeaderParam.ALG: 10}, b'A1010A'),
                             pytest.param({CoseHeaderParam.ALG: None}, b'A1010A', marks=pytest.mark.xfail),
                             ({CoseHeaderParam.ALG: CoseAlgorithm.AES_CCM_16_128_128}, b'A101181E')
                         ])
def test_indirect_phdr_creation(params, encoded_phdr):
    enc0_msg = Enc0Message()
    enc0_msg.phdr = params

    outcome = enc0_msg.encode_phdr()
    assert outcome == unhexlify(encoded_phdr)


@pytest.mark.parametrize("params, encoded_uhdr",
                         [
                             ({1: 10}, {1: 10}),
                             ({CoseHeaderParam.ALG: 10}, {1: 10}),
                             ({CoseHeaderParam.ALG: CoseAlgorithm.AES_CCM_16_64_128}, {1: 10}),
                             ({1: CoseAlgorithm.AES_CCM_16_64_128}, {1: 10}),
                             ({CoseHeaderParam.ALG: 10, CoseHeaderParam.IV: b'02D1F7E6F26C43D4868D87CE'},
                              {1: 10, 5: b'02D1F7E6F26C43D4868D87CE'}),
                             ({CoseHeaderParam.PARTIAL_IV: b'61a7'}, {6: b'61a7'}),
                             pytest.param({1: None}, b'A1010A', marks=pytest.mark.xfail),
                             pytest.param(None, {}, marks=pytest.mark.xfail(reason="setter value must be of type dict"))
                         ])
def test_indirect_uhdr_creation(params, encoded_uhdr):
    enc0_msg = Enc0Message()
    enc0_msg.uhdr = params

    outcome = enc0_msg.encode_uhdr()
    assert outcome == encoded_uhdr


@pytest.mark.parametrize("params, encoded_uhdr",
                         [
                             ({1: 1, 5: b'02D1F7E6F26C43D4868D87CE'}, {1: 1, 5: b'02D1F7E6F26C43D4868D87CE'}),
                             ({CoseHeaderParam.ALG: 10, CoseHeaderParam.IV: b'02D1F7E6F26C43D4868D87CE'},
                              {1: 10, 5: b'02D1F7E6F26C43D4868D87CE'}),
                             ({CoseHeaderParam.ALG: CoseAlgorithm.A256GCM, CoseHeaderParam.IV: b'ae8987be9874f98ebb'},
                              {1: 3, 5: b'ae8987be9874f98ebb'}),
                         ])
def test_update_uhdr(params, encoded_uhdr):
    enc0_msg = Enc0Message()
    enc0_msg.uhdr_update(params)

    outcome = enc0_msg.encode_uhdr()
    assert outcome == encoded_uhdr


@pytest.mark.parametrize("param1, param2, expected", [({1: 10}, {1: 1}, {1: 1})])
def test_overwrite_attr_uhdr(param1, param2, expected):
    enc0_msg = Enc0Message()
    enc0_msg.uhdr_update(param1)
    enc0_msg.uhdr_update(param2)

    assert enc0_msg.encode_uhdr() == expected


@pytest.mark.parametrize("param1, param2, expected", [({1: 1}, {1: 10}, b'A1010A')])
def test_overwrite_attr_phdr(param1, param2, expected):
    enc0_msg = Enc0Message()
    enc0_msg.phdr_update(param1)
    enc0_msg.phdr_update(param2)

    assert enc0_msg.encode_phdr() == unhexlify(expected)


@pytest.mark.parametrize("params, expected", [({1: -25}, b'a1013818'),
                                              ({1: CoseAlgorithm.ES256}, b'a10126'),
                                              ({'reserved': False, 2: ["reserved"]},
                                               b'a2687265736572766564f40281687265736572766564'),
                                              ({CoseHeaderParam.ALG: CoseAlgorithm.EDDSA,
                                                CoseHeaderParam.CONTENT_TYPE: 0}, b'A201270300'),
                                              (None, b'')
                                              ])
def test_direct_phdr_creation(params, expected):
    enc0_msg = Enc0Message(phdr=params)
    assert enc0_msg.encode_phdr() == unhexlify(expected)


@pytest.mark.parametrize("params, expected",
                         [
                             ({1: CoseAlgorithm.DIRECT, CoseHeaderParam.KID: b'our-secret'}, {1: -6, 4: b'our-secret'}),
                             ({CoseHeaderParam.KID: 11}, {4: 11}),
                             (None, {})
                         ])
def test_direct_uhdr_creation(params, expected):
    enc0_msg = Enc0Message(uhdr=params)
    assert enc0_msg.encode_uhdr() == expected