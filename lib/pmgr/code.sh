# shellcheck shell=bash
# Where to fix it: find the line in your repos that defines each finding's resource, in local
# clones (fast, offline, no API calls). Terraform repos are searched for the resource's quoted
# name ("orders-prd"); GitOps repos for "name: api" in YAML. Names built by interpolation
# ("${var.env}-orders") can't be matched, so this is best-effort: no match means "not found", not
# "not in code".

CODE_ROOTS="src code git repos Projects projects work dev"

# code_repo_path NAME : the local clone of a configured repo (its path, or found in a usual place).
code_repo_path() {
  local name=$1 short p r
  p=$(jq -r --arg n "$name" '[.github.repos // [] | .[] | select(.name == $n) | .path // empty] | first // ""' <<<"$PMGR_CONFIG_JSON")
  if [ -n "$p" ]; then
    p=${p/#\~/$HOME}
    [ -d "$p" ] && printf '%s' "$p"
    return 0
  fi
  short=${name##*/}
  for r in $CODE_ROOTS ""; do
    p="$HOME/${r:+$r/}$short"
    if [ -d "$p/.git" ]; then printf '%s' "$p"; return 0; fi
  done
  return 0
}

# code_repos : one line per configured repo that has a local clone: NAME<tab>KIND<tab>PATH<tab>URL_BASE
code_repos() {
  local name kind path branch slug
  while IFS=$'\t' read -r name kind; do
    [ -n "$name" ] || continue
    path=$(code_repo_path "$name")
    [ -n "$path" ] || continue
    branch=$(git -C "$path" symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null | sed 's#^origin/##')
    slug=$(gh_slug "$name")
    printf '%s\t%s\t%s\thttps://github.com/%s/blob/%s\n' "$name" "$kind" "$path" "$slug" "${branch:-main}"
  done < <(jq -r '.github.repos // [] | .[] | [.name, (.kind // "other")] | @tsv' <<<"$PMGR_CONFIG_JSON")
}

# code_search PATH KIND NEEDLE : up to 3 "file<tab>line" matches, relative to PATH.
code_search() {
  local path=$1 kind=$2 needle=$3
  case $kind in
    gitops)
      grep -rnE --include='*.yaml' --include='*.yml' --exclude-dir=.git \
        "^[[:space:]-]*name:[[:space:]]*[\"']?$(printf '%s' "$needle" | sed 's/[.[\*^$()+?{|]/\\&/g')[\"']?[[:space:]]*(#.*)?$" "$path" 2>/dev/null ;;
    *)
      grep -rnF --include='*.tf' --include='*.tfvars' --include='*.hcl' --include='*.json' \
        --exclude-dir=.git --exclude-dir=.terraform --exclude-dir=node_modules "\"$needle\"" "$path" 2>/dev/null ;;
  esac | head -n 3 | sed -E "s#^$path/##; s#^([^:]+):([0-9]+):.*#\\1\\t\\2#"
}

# code_locate REPORT : the report with {where: [{repo, path, line, url}]} on findings whose resource
# was found in a local clone.
code_locate() {
  local report=$1 repos needles map="{}" kind needle name rkind path base file line hits
  repos=$(code_repos)
  [ -n "$repos" ] || { printf '%s' "$report"; return 0; }
  # What to look for, per finding: names that appear in code (never ARNs or generated IDs).
  needles=$(jq -r '
    def ok: type == "string" and length >= 3 and (test("^(arn:|i-|vol-|sg-|snap-|eni-|subnet-|vpc-|f[0-9]+$)") | not) and (test("[ /]") | not);
    .findings[] | .id as $id | (.diag // {}) as $d
    | ([ (if ($d.type // "") | IN("pod", "workload", "object", "argo", "tgb") then {k: "gitops", n: $d.name} else empty end),
         (if ($d.type // "") | IN("rds", "redshift", "elasticache", "msk", "eks", "s3", "lb", "iam_role", "iam_user", "cluster") then {k: "terraform", n: ($d.id // $d.cluster)} else empty end),
         (if ($d.type // "") == "eks_nodegroup" then {k: "terraform", n: $d.nodegroup} else empty end),
         (if ($d.type // "") == "eks_addon" then {k: "terraform", n: $d.addon} else empty end),
         (if .check == "tgb.target_group_missing" then {k: "terraform", n: (.evidence.closest // .evidence.wanted)} else empty end),
         (if ($d.type // "") == "tgb" and (.evidence.wanted // null) == null then {k: "terraform", n: (.message | capture("target group (?<t>[A-Za-z0-9-]+)").t // empty)} else empty end),
         (if ($d.type // "") | IN("acm", "cloudfront", "secret") then {k: "terraform", n: (.resource | split("/") | last)} else empty end)
       ] | map(select(.n | ok)) | unique[]) | [$id, .k, .n] | @tsv' <<<"$report" 2>/dev/null)
  [ -n "$needles" ] || { printf '%s' "$report"; return 0; }
  # Search each (kind, name) once, in every clone of a matching kind ("other" repos get Terraform searches).
  while IFS=$'\t' read -r kind needle; do
    hits="[]"
    while IFS=$'\t' read -r name rkind path base; do
      case "$kind:$rkind" in gitops:gitops | terraform:terraform | terraform:other) ;; *) continue ;; esac
      while IFS=$'\t' read -r file line; do
        [ -n "$file" ] || continue
        hits=$(jq -c --arg repo "$name" --arg f "$file" --argjson l "$line" --arg url "$base/$file#L$line" \
          '. + [{repo: $repo, path: $f, line: $l, url: $url}]' <<<"$hits")
      done < <(code_search "$path" "$rkind" "$needle")
    done <<<"$repos"
    map=$(jq -c --arg k "$kind|$needle" --argjson h "$hits" '. + {($k): $h}' <<<"$map")
  done < <(cut -f2,3 <<<"$needles" | sort -u)
  jq -c --argjson map "$map" --arg needles "$needles" '
    ($needles | split("\n") | map(select(. != "") | split("\t")) | group_by(.[0]) | map({key: .[0][0], value: [.[] | "\(.[1])|\(.[2])"]}) | from_entries) as $want
    | .findings |= map(. as $f | ([($want[$f.id] // [])[] | $map[.][]?] | unique_by("\(.repo)/\(.path):\(.line)") | .[0:3]) as $w
        | if ($w | length) > 0 then . + {where: $w} else . end)' <<<"$report"
}
