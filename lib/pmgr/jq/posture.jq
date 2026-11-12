# Shared by the posture rules (edge, data, identity, compute).
# $cfg: {tag, public_envs, account_env, allowed} like the security check's, plus {label, region}.

def low: (. // "") | tostring | ascii_downcase;

# A tag's value from AWS's [{Key, Value}] list or a {key: value} map.
def tagv($cfg; $tags): ($cfg.tag | low) as $k
  | if ($tags | type) == "array" then ([$tags[]? | select((.Key // .key | low) == $k) | (.Value // .value)] | first)
    elif ($tags | type) == "object" then ([$tags | to_entries[] | select(.key | low == $k) | .value] | first)
    else null end;

# The environment a name implies: prd, prod, uat, rc, dev, … as a whole word in it.
def env_from_name: low | (capture("(^|[-_./])(?<e>prd|prod|production|uat|rc|stg|stage|staging|dev|qa|test)([-_./]|$)") // {}).e;

# Environment: its own tag, then its VPC's tag, then the account's configured one, then its name.
def env_of($cfg; $tags; $vpc_env; $name):
  tagv($cfg; $tags) // $vpc_env // $cfg.account_env[$cfg.label] // ($name | env_from_name);

def is_prd($cfg; $e): ($e != null) and ([$cfg.public_envs[] | low] | index($e | low)) != null;
def listed($cfg; $id): ($cfg.allowed // []) | index($id) != null;

def day: .[0:10] + "T00:00:00Z" | fromdateiso8601;
def days_ago($now; $t): if $t == null then null else (($now - ($t | day)) / 86400 | floor) end;
def days_left($now; $t): if $t == null then null else ((($t | day) - $now) / 86400 | floor) end;
def money: . * 100 | round / 100;
# Dollars with cents, the same on every jq build.
def usd: (. * 100 | round) as $c | "\($c / 100 | floor).\($c % 100 | tostring | if length == 1 then "0" + . else . end)";
def plural($n; $one; $many): "\($n) \(if $n == 1 then $one else $many end)";
def names($n): if length <= $n then join(", ") else (.[0:$n] | join(", ")) + " and \(length - $n) more" end;
