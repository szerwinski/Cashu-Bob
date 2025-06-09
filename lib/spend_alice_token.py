import hashlib
import json
import secrets
import requests
import secp256k1
from secp256k1_ext import *  # Importa o monkeypatching

# Configurações
MINT_URL = "http://localhost:3338"  # Mint A
KEYSET_ID = "000b4c3d8b0e7397"  # Keyset da Mint A
ALICE_PUBLIC_KEY = "02c776bf1be8e58e9b900ecb9bd414fe48fe99bad2cb76754d39c2c3c7b519a2e5"
DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"

# Passo 1: Carregar a assinatura de Alice
with open("/Users/szerwinski/dev/Bitcoin/TCC/nutshell_bob/schnorr_signature_alice_by_bob.json", "r") as f:
    alice_signature = json.load(f)
Radaptor = alice_signature["Radaptor"]
s = alice_signature["s"]
schnorr_signature = Radaptor + s  # Concatenar para 64 bytes
print(f"Assinatura Schnorr de Alice (Radaptor || s): {schnorr_signature}")

# Passo 2: Carregar o proof de Alice (Mint A, 8 sats)
with open("/Users/szerwinski/dev/Bitcoin/TCC/nutshell/p2pk_unblinded_proofs.json", "r") as f:
    proofs = json.load(f)
proof = next(p for p in proofs if p["amount"] == 8)
print(f"Proof de Alice: {proof}")

# Verificar se o secret contém a chave pública correta
secret_json = json.loads(proof["secret"])
if secret_json[1]["data"] != ALICE_PUBLIC_KEY:
    raise ValueError(f"Chave pública no secret de Alice não corresponde: {secret_json[1]['data']}")

# Passo 3: Validar a assinatura
Pa = secp256k1.PublicKey(bytes.fromhex(ALICE_PUBLIC_KEY), raw=True)
message = hashlib.sha256(proof["secret"].encode('utf-8')).digest()
try:
    is_valid = Pa.schnorr_verify(message, bytes.fromhex(schnorr_signature), None, raw=True)
    print(f"Assinatura válida: {is_valid}")
    if not is_valid:
        raise ValueError("Assinatura Schnorr de Alice inválida.")
except Exception as e:
    print(f"Erro ao verificar a assinatura Schnorr: {e}")
    raise

# Passo 4: Preparar o proof com witness
witness = {
    "signatures": [schnorr_signature]
}
print(f"Witness gerado: {json.dumps(witness, indent=2)}")
proof_with_witness = {
    "amount": proof["amount"],
    "id": proof["id"],
    "secret": proof["secret"],
    "C": proof["C"],
    "witness": json.dumps(witness)
}

# Passo 5: Gerar novos outputs (2 tokens de 4 sats)
outputs = []
new_amounts = [4, 4]
secrets_list = []
r_scalars = []

def hash_to_curve(x: bytes, counter=0) -> secp256k1.PublicKey:
    """Converte um segredo em um ponto Y na curva usando hash_to_curve, conforme Cashu."""
    msg_to_hash = hashlib.sha256(DOMAIN_SEPARATOR + x).digest()
    while counter < 2**16:
        _hash = hashlib.sha256(msg_to_hash + counter.to_bytes(4, "little")).digest()
        try:
            Y = secp256k1.PublicKey(b"\x02" + _hash, raw=True)
            print(f"Ponto Y encontrado com counter: {counter}, prefix: 02")
            return Y
        except Exception:
            counter += 1
    raise ValueError("No valid point found after 2**16 iterations.")

for amount in new_amounts:
    x = secrets.token_bytes(32)
    secrets_list.append(x)
    print(f"Secret para novo output ({amount} sats): {x.hex()}")

    Y = hash_to_curve(x)
    print(f"Y: {Y.serialize().hex()}")

    r = secp256k1.PrivateKey()
    r_scalar = int.from_bytes(r.private_key, 'big')
    r_scalars.append(r_scalar)
    print(f"r_scalar: {r_scalar}")
    print(f"r.pubkey: {r.pubkey.serialize().hex()}")

    B_ = Y + r.pubkey
    print("Adição de pontos bem-sucedida")

    B_serialized = B_.serialize().hex()
    print(f"B_: {B_serialized}")

    outputs.append({
        "amount": amount,
        "id": KEYSET_ID,
        "B_": B_serialized
    })

# Passo 6: Salvar os dados dos novos outputs
swap_data = {
    "outputs": outputs,
    "secrets": [s.hex() for s in secrets_list],
    "r_scalars": r_scalars
}
with open("/Users/szerwinski/dev/Bitcoin/TCC/nutshell_bob/swap_outputs_data_bob.json", "w") as f:
    json.dump(swap_data, f, indent=4)
print("Novos outputs, secrets e r_scalars salvos em swap_outputs_data_bob.json")

# Passo 7: Enviar o pedido de swap
payload = {
    "inputs": [proof_with_witness],
    "outputs": outputs
}
headers = {"Content-Type": "application/json"}
print(f"Payload enviado: {json.dumps(payload, indent=2)}")
try:
    response = requests.post(f"{MINT_URL}/v1/swap", json=payload, headers=headers)
    print(f"Resposta da mint: {response.status_code}")
    print(f"Conteúdo da resposta: {response.text}")

    if response.status_code == 200:
        swap_response = response.json()
        with open("/Users/szerwinski/dev/Bitcoin/TCC/nutshell_bob/swap_response_bob.json", "w") as f:
            json.dump(swap_response, f, indent=4)
        print("Swap bem-sucedido! Resposta salva em swap_response_bob.json")
    else:
        print("Swap falhou. Verifique o proof ou a mint.")
except requests.exceptions.RequestException as e:
    print(f"Erro na requisição de swap: {e}")