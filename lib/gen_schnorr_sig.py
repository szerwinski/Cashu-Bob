import hashlib
import json
import secp256k1
from secp256k1_ext import *  # Importa o monkeypatching

# Configurações
BOB_PRIVATE_KEY = "ff477dcb0152412435d6813b5ffb64d9af1a60a6c7a5cc04dd3a9c8cf9085b12"
BOB_PUBLIC_KEY = "02c15e12abf164078fd114c72b679ce186f0338de7086c559422297a76b432f447"
ALICE_PUBLIC_KEY = "02c776bf1be8e58e9b900ecb9bd414fe48fe99bad2cb76754d39c2c3c7b519a2e5"
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAaedce6af48a03bbfd25e8cd0364141

# Verificar consistência da chave de Bob
kb = secp256k1.PrivateKey(bytes.fromhex(BOB_PRIVATE_KEY))
if kb.pubkey.serialize().hex() != BOB_PUBLIC_KEY:
    raise ValueError("A chave privada de Bob não corresponde à chave pública fornecida!")

# Passo 1: Carregar o proof descegado
with open("p2pk_unblinded_proofs_bob.json", "r") as f:
    proofs = json.load(f)

# Pegar o proof de 8 sats
proof = next(p for p in proofs if p["amount"] == 8)
x = proof["secret"]  # O secret P2PK (string JSON)
print(f"Secret a ser assinado (x): {x}")

# Verificar se o secret é multisig com Bob e Alice
secret_json = json.loads(x)
tags = secret_json[1]["tags"]
if not (
    secret_json[1]["data"] == BOB_PUBLIC_KEY and
    ["n_sigs", "2"] in tags and
    ["pubkeys", ALICE_PUBLIC_KEY] in tags
):
    raise ValueError("Secret não é um P2PK multisig com as chaves de Bob e Alice! Detalhes: data={}, tags={}".format(
        secret_json[1]["data"], tags))

# Passo 2: Gerar a assinatura Schnorr t usando schnorr_sign
Pb = secp256k1.PublicKey(bytes.fromhex(BOB_PUBLIC_KEY), raw=True)
x_hash = hashlib.sha256(x.encode('utf-8')).digest()  # H(x)
try:
    t = kb.schnorr_sign(x_hash, None, raw=True)
    t_hex = t.hex()
    print(f"Assinatura (t): {t_hex}")

    # Extrair R_b (coordenada x) dos primeiros 32 bytes da assinatura
    Rb_x = t[:32]  # Primeiros 32 bytes
    Rb = secp256k1.PublicKey(b"\x02" + Rb_x, raw=True)  # Reconstruir ponto com prefixo 02
    print(f"Nonce público (Rb): {Rb_x.hex()}")

    # Validar a assinatura
    is_valid = Pb.schnorr_verify(x_hash, t, None, raw=True)
    print(f"Assinatura válida: {is_valid}")
    if not is_valid:
        raise ValueError("Assinatura Schnorr de Bob inválida.")
except Exception as e:
    print(f"Erro ao gerar ou verificar a assinatura Schnorr: {e}")
    raise

# Passo 3: Salvar a assinatura e Rb
signature = {
    "Rb": Rb_x.hex(),  # Apenas coordenada x
    "t": t_hex
}
with open("schnorr_signature_bob.json", "w") as f:
    json.dump(signature, f, indent=4)
print("Assinatura salva em schnorr_signature_bob.json")