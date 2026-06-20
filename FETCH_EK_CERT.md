# Fetching and verifying an EK certificate on an AMD fTPM client

Run on each candidate client PC. Determines whether the machine can reach Tier 1.

## Prerequisites
```
sudo apt install tpm2-tools openssl curl
```

## Step 0 - does this device even have a fetchable EK cert?
```
tpm2_createek -c ek.ctx -G rsa -u ek.pub
tpm2_getekcertificate -u ek.pub -o ek.crt -X 2>/dev/null
[ -s ek.crt ] && echo "HAS EK CERT" || echo "NO EK CERT"
```
NO EK CERT (consistent across 2-3 retries; AMD's server is flaky) means this machine
caps at Tier 2. Stop here for that client. HAS EK CERT means continue.

## Step 1-2 - create EK pub, fetch the cert (done above)
`ek.crt` is now the machine's EK certificate (DER).

## Step 3 - find the intermediate CA URL (per-machine, read it, do not copy)
```
openssl x509 -in ek.crt -inform DER -text -noout | grep -A1 "CA Issuers"
```
Copy the URI it prints.

## Step 4 - fetch the intermediate
```
curl -o amd_ca.crt "<URI from step 3>"
```

## Step 5 - find the root CA URL
```
openssl x509 -in amd_ca.crt -inform DER -text -noout | grep -A1 "CA Issuers"
```

## Step 6 - fetch the root
```
curl -o amd_root.crt "<URI from step 5>"
```

## Step 7 - convert to PEM and verify the full chain
```
openssl x509 -in ek.crt      -inform DER -out ek.pem
openssl x509 -in amd_ca.crt   -inform DER -out prg_rn.pem
openssl x509 -in amd_root.crt -inform DER -out amdtpm.pem
openssl verify -CAfile amdtpm.pem -untrusted prg_rn.pem ek.pem
```
`ek.pem: OK` confirms Tier-1 capability.

## Step 8 - build the CA bundle and confirm the tier in DLTF
```
mkdir -p tpm/ca
cat prg_rn.pem amdtpm.pem > tpm/ca/amd_ftpm_ca.pem
PYTHONPATH=. python3 -m tpm.check_ek_cert --ek-cert ek.crt --ca-bundle tpm/ca/amd_ftpm_ca.pem
```

## Notes for additional clients
- Step 3/5 hashes are per-machine; always read them, never reuse another machine's.
- The PRG-RN intermediate is shared across same-generation AMD chips and the AMDTPM
  root is shared by all, so once you have tpm/ca/amd_ftpm_ca.pem, other AMD machines
  of the same family usually verify against the SAME bundle - only their ek.crt differs.
  Test it: if a new client's ek.crt verifies against the existing bundle, skip 4-6.
- Non-AMD TPMs (Intel, discrete) use different CA URLs; the cert's own CA Issuers field
  always says where to look.
- ek.crt and tpm/ca/amd_ftpm_ca.pem are thesis artifacts; keep them.



## ANOTHER METHOD

# ============================================================
#  AMD fTPM — Fetch & Verify EK Certificate (Tier 1 proof)
#  Run from your project root. Every cert lands in cert/.
# ============================================================

# --- Step 0: make folder, ask the chip for its EK cert ---
sudo mkdir -p cert
sudo tpm2_createek -c cert/ek.ctx -G rsa -u cert/ek.pub
sudo tpm2_getekcertificate -u cert/ek.pub -o cert/ek.crt -X
[ -s cert/ek.crt ] && echo "HAS EK CERT ($(stat -c%s cert/ek.crt) bytes)" || echo "NO EK CERT"
#  NO EK CERT after 2-3 tries  -> this box caps at Tier 2, STOP.
#  HAS EK CERT                 -> continue.

# --- Step 1: convert your cert to PEM ---
sudo openssl x509 -in cert/ek.crt -inform DER -out cert/ek.pem

# --- Step 2: read the INTERMEDIATE CA url from your cert ---
sudo openssl x509 -in cert/ek.crt -inform DER -text -noout | grep -A1 "CA Issuers"
#  Copy the  URI:http://...  it prints.  <-- this is YOUR url

# --- Step 3: fetch the intermediate, convert it ---
sudo curl -fL -o cert/amd_ca.crt "<INTERMEDIATE_URI from step 2>"
sudo openssl x509 -in cert/amd_ca.crt -inform DER -out cert/prg_rn.pem

# --- Step 4: read the ROOT CA url from the intermediate ---
sudo openssl x509 -in cert/prg_rn.pem -text -noout | grep -A1 "CA Issuers"
#  Copy the  URI:http://...  it prints.  <-- root url

# --- Step 5: fetch the root, convert it ---
sudo curl -fL -o cert/amd_root.crt "<ROOT_URI from step 4>"
sudo openssl x509 -in cert/amd_root.crt -inform DER -out cert/amdtpm.pem

# --- Step 6: verify the full chain ---
sudo openssl verify -CAfile cert/amdtpm.pem -untrusted cert/prg_rn.pem cert/ek.pem \
  || sudo openssl verify -partial_chain -CAfile cert/amdtpm.pem -untrusted cert/prg_rn.pem cert/ek.pem
#  Success = "cert/ek.pem: OK"

# --- Step 7: build the CA bundle your code loads, fix ownership ---
sudo bash -c 'cat cert/prg_rn.pem cert/amdtpm.pem > cert/amd_ftpm_ca.pem'
sudo chown $USER:$USER cert/*

# --- Step 8 (optional): confirm DLTF's own verifier accepts it ---
PYTHONPATH=. python3 -c "
from tpm.common import verify_ek_certificate
ok = verify_ek_certificate(open('cert/ek.pem','rb').read(), open('cert/amd_ftpm_ca.pem','rb').read())
print('DLTF verify:', 'OK' if ok else 'FAIL')
"

mkdir -p tpm/ca && cp cert/amd_ftpm_ca.pem tpm/ca/