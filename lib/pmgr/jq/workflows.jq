def triggers: (.on // null) as $on
  | if ($on | type) == "string" then [$on] elif ($on | type) == "array" then $on
    elif ($on | type) == "object" then ($on | keys) else [] end;
def jobs: (.jobs // {}) | if type == "object" then . else {} end;
def steps: (.steps // []) | if type == "array" then map(select(type == "object")) else [] end;
def runs: [jobs[] | steps[] | (.run // "") | tostring] | join("\n");
def uses: [jobs[] | (if (.uses | type) == "string" then {u: .uses, w: {}} else empty end),
                    (steps[] | select((.uses | type) == "string") | {u: .uses, w: (.with // {})})];
def tf_apply: test("\\bterraform\\s+apply\\b|\\bterragrunt\\s+(run-all\\s+)?apply\\b");
def tf_plan: test("\\bterraform\\s+plan\\b|\\bterragrunt\\s+(run-all\\s+)?plan\\b|terraform-plan|tfc-workflows|atlantis"; "i");
def deploys: test("\\bterraform\\s+apply\\b|\\bkubectl\\s+apply\\b|\\bhelm\\s+(upgrade|install)\\b|\\bargocd\\s+app\\s+sync\\b|\\bdocker\\s+push\\b|\\baws\\s+(s3\\s+sync|ecs\\s+update-service|cloudfront\\s+create-invalidation)\\b");
def injectable: "\\$\\{\\{\\s*github\\.(head_ref|event\\.(pull_request|issue|comment|review|review_comment|head_commit|discussion)\\.[\\w.]*(title|body|message|name|label|ref|email))\\s*\\}\\}";
