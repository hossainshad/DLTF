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

1. Install tools:
sudo apt update
sudo apt install -y tpm2-tools openssl curl python3 python3-pip
pip install numpy cryptography --break-system-packages
2. Go to the project folder:
cd ~/Documents/thesis/dltf      # adjust path to where you copied it
3. Check the TPM is present:
ls /dev/tpm*                    # should list /dev/tpm0 and/or /dev/tpmrm0
If nothing appears, the TPM is off in BIOS — stop, enable fTPM in BIOS, retry.
4. Generate EK public key and try to fetch the cert:
tpm2_createek -c ek.ctx -G rsa -u ek.pub
tpm2_getekcertificate -u ek.pub -o ek.crt -X 2>/dev/null
[ -s ek.crt ] && echo "HAS EK CERT" || echo "NO EK CERT"

NO EK CERT (retry 2-3 times; AMD server is flaky) → this laptop caps at Tier 2. Skip to step 9.
HAS EK CERT → continue.

5. Find the intermediate CA URL (unique to this machine — read it):
openssl x509 -in ek.crt -inform DER -text -noout | grep -A1 "CA Issuers"
Copy the http://ftpm.amd.com/pki/aia/... URL it prints.
6. Fetch the intermediate (paste that URL):
curl -o amd_ca.crt "PASTE_INTERMEDIATE_URL_HERE"
7. Find the root CA URL, then fetch the root:
openssl x509 -in amd_ca.crt -inform DER -text -noout | grep -A1 "CA Issuers"
curl -o amd_root.crt "PASTE_ROOT_URL_HERE"
8. Convert to PEM, verify the chain, build the bundle:
openssl x509 -in ek.crt      -inform DER -out ek.pem
openssl x509 -in amd_ca.crt   -inform DER -out prg_rn.pem
openssl x509 -in amd_root.crt -inform DER -out amdtpm.pem
openssl verify -CAfile amdtpm.pem -untrusted prg_rn.pem ek.pem
mkdir -p tpm/ca
cat prg_rn.pem amdtpm.pem > tpm/ca/amd_ftpm_ca.pem
Expect ek.pem: OK.
9. Confirm the tier through your project:
PYTHONPATH=. python3 -m tpm.check_ek_cert --ek-cert ek.crt --ca-bundle tpm/ca/amd_ftpm_ca.pem
→ Tier 1 HARDWARE if steps 4-8 succeeded, or Tier 2 if no cert.

Two shortcuts worth knowing:

If your friend's laptop is also a same-generation AMD (Ryzen 5000-series), its EK cert likely chains to the same PRG-RN + AMDTPM bundle you already built. Try the bundle you already have first — copy your tpm/ca/amd_ftpm_ca.pem over, then just do steps 4 and 9. If step 9 says Tier 1, you can skip steps 5-8 entirely. Only if it fails do you fetch that machine's own CA URLs.
Different CPU vendor (Intel, or a discrete TPM): steps 5-7 URLs will point somewhere else entirely — that's fine, the cert's own "CA Issuers" field always tells you where. The procedure is identical; only the URLs differ.

Paste the step-9 output from the friend's machine and I'll confirm what tier it landed on.