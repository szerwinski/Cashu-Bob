import hashlib
import json
import secp256k1
from secp256k1_ext import *  # Importa o monkeypatching

# Configurações
BOB_PRIVATE_KEY = "ff477dcb0152412435d6813b5ffb64d9af1a60a6c7a5cc04dd3a9c8cf9085b12"
BOB_PUBLIC_KEY = "02c15e12abf164078fd114c72b679ce186f0338de7086c559422297a76b432f447"
ALICE_PUBLIC_KEY = "02c776bf1be8e58e9b900ecb9bd414fe48fe99bad2cb76754d39c2c3c7b519a2e5"
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAaedce6af48a03bbfd25e8cd0364141

# Passo 1: Carregar t de Bob
with open("schnorr_signature_bob.json", "r") as f:
    bob_signature = json.load(f)
t = bytes.fromhex(bob_signature["t"])
Rb = bytes.fromhex(bob_signature["Rb"])
print(f"t (Bob): {t.hex()}")
print(f"Rb (Bob): {Rb.hex()}")

# Extrair s_b (últimos 32 bytes de t)
s_b = t[32:]  # Últimos 32 bytes
print(f"s_b (escalar de t): {s_b.hex()}")

# Passo 2: Carregar (Radaptor, sa) de Alice
with open("/Users/szerwinski/dev/Bitcoin/TCC/nutshell/adaptor_signature_alice.json", "r") as f:
    alice_signature = json.load(f)
Radaptor = bytes.fromhex(alice_signature["Radaptor"])
sa = bytes.fromhex(alice_signature["sa"])
print(f"Radaptor (Alice): {Radaptor.hex()}")
print(f"sa (Alice): {sa.hex()}")

# Passo 3: Carregar o secret do proof de Alice (Mint A, 8 sats)
with open("/Users/szerwinski/dev/Bitcoin/TCC/nutshell/p2pk_unblinded_proofs.json", "r") as f:
    proofs = json.load(f)
proof = next(p for p in proofs if p["amount"] == 8)
y = proof["secret"]  # O secret P2PK de Alice
print(f"Secret do proof de Alice (y): {y}")

# Passo 4: Calcular s = sa + t
sa_int = int.from_bytes(sa, 'big') % CURVE_ORDER
s_b_int = int.from_bytes(s_b, 'big') % CURVE_ORDER
s = (sa_int + s_b_int) % CURVE_ORDER
s_bytes = s.to_bytes(32, 'big')
print(f"Assinatura válida de Alice (s): {s_bytes.hex()}")

# Passo 5: Validar a assinatura s
Pa = secp256k1.PublicKey(bytes.fromhex(ALICE_PUBLIC_KEY), raw=True)
message = hashlib.sha256(y.encode('utf-8')).digest()
try:
    is_valid = Pa.schnorr_verify(message, Radaptor + s_bytes, None, raw=True)
    print(f"Assinatura s válida: {is_valid}")
    if not is_valid:
        raise ValueError("Assinatura Schnorr s inválida.")
except Exception as e:
    print(f"Erro ao verificar a assinatura s: {e}")
    raise

# Passo 6: Salvar a assinatura Schnorr
signature = {
    "Radaptor": Radaptor.hex(),
    "s": s_bytes.hex()
}
with open("schnorr_signature_alice_by_bob.json", "w") as f:
    json.dump(signature, f, indent=4)
print("Assinatura salva em schnorr_signature_alice_by_bob.json")