# shellcheck shell=bash
# Why a GitHub Actions job failed: the step, the error line, and a fix only when it's certain.
#
# The error line is nearly always enough to turn "the pipeline is red" into a task.
# A suggested fix is a claim, so it's only made for failures whose cause isn't ambiguous.

# error_line LOGFILE : the most specific error in a job log.
error_line() {
  awk '
    {
      line = $0
      sub(/^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9:.]+Z ?/, "", line)
      gsub(/\033\[[0-9;]*[A-Za-z]/, "", line)
      gsub(/│|╷|╵/, "", line)
      gsub(/^[ \t]+|[ \t]+$/, "", line)
      i = index(line, "##[error]")
      if (i > 0) {
        msg = substr(line, i + 9)
        gsub(/^[ \t]+|[ \t]+$/, "", msg)
        if (msg == "") next
        gh_last = msg
        if (tolower(msg) !~ /process completed with exit code [0-9]+/) specific = msg
      } else if (line ~ /^(Error|ERROR|FAILED|fatal|FATAL)[: \t]/) {
        msg = line
        sub(/^(Error|ERROR|FAILED|fatal|FATAL)[: \t][ \t]*/, "", msg)
        tool = msg
      }
    }
    END {
      if (specific != "") print substr(specific, 1, 400)
      else if (tool != "") print substr(tool, 1, 400)
      else print substr(gh_last, 1, 400)
    }' "$1"
}

# diagnose LOGFILE : prints a JSON {id, cause, fix} for a certain cause, or nothing.
diagnose() {
  local low id="" cause="" fix=""
  low=$(tr '[:upper:]' '[:lower:]' <"$1")
  # Canceled: the only errors are the cancellation itself.
  if printf '%s' "$low" | grep -qF "the operation was canceled" &&
    ! printf '%s' "$low" | grep -F "##[error]" | grep -qvF "the operation was canceled"; then
    jq -cn '{id: "canceled", cause: "The run was canceled, usually by a newer run.", fix: ""}'
    return 0
  fi
  has() { printf '%s' "$low" | grep -qF -- "$1"; }
  if has "error acquiring the state lock"; then
    id=tf_state_lock cause="Terraform state is locked by another run."
    fix='Check for a concurrent run of this workflow. If none is running, confirm the lock ID in the log and run `terraform force-unlock <ID>`. Add a `concurrency:` group so runs can'"'"'t overlap.'
  elif has "inconsistent dependency lock file"; then
    id=tf_lock_file cause="The Terraform lock file doesn't match the configured providers."
    fix='Run `terraform init -upgrade` locally and commit `.terraform.lock.hcl`.'
  elif has "not authorized to perform sts:assumerolewithwebidentity"; then
    id=oidc_trust cause="AWS rejected the GitHub OIDC token: the role's trust policy doesn't match this repo, branch or event."
    fix='Compare the role'"'"'s `token.actions.githubusercontent.com:sub` condition with this run'"'"'s repo and ref (pull requests use `repo:ORG/REPO:pull_request`).'
  elif has "could not load credentials from any providers" || has "unable to get actions_id_token_request_url"; then
    id=oidc_permission cause="The job couldn't request an OIDC token."
    fix='Add `permissions: id-token: write` to the workflow or job.'
  elif has "expiredtoken" || has "security token included in the request is expired"; then
    id=aws_expired_mid_run cause="AWS credentials expired during the run."
    fix='The job ran longer than the role'"'"'s session duration. Raise the role'"'"'s max session duration and `role-duration-seconds`, or split the job.'
  elif has "resource not accessible by integration"; then
    id=token_permission cause="GITHUB_TOKEN lacks a permission this step needs."
    fix='Grant the specific scope in the workflow'"'"'s `permissions:` block (for example `pull-requests: write`).'
  elif has "toomanyrequests" || has "pull rate limit"; then
    id=docker_rate_limit cause="Docker Hub rate-limited the image pull."
    fix="Log in to Docker Hub in the job, or pull through an ECR pull-through cache."
  elif has "exit code 137" || has "killed signal" || has "javascript heap out of memory"; then
    id=out_of_memory cause="The job ran out of memory."
    fix="Use a larger runner, or lower the build's parallelism."
  elif has "no space left on device"; then
    id=disk_full cause="The runner ran out of disk."
    fix="Prune images and caches in the job, or use a runner with more disk."
  elif has "has exceeded the maximum execution time"; then
    id=job_timeout cause="The job hit its timeout."
    fix='Find the slow step in the log. Raise `timeout-minutes` only if the work genuinely takes longer.'
  fi
  [ -n "$id" ] && jq -cn --arg id "$id" --arg cause "$cause" --arg fix "$fix" '{id: $id, cause: $cause, fix: $fix}'
  return 0
}

# explain JOB_JSON LOGFILE : everything known about one failed job.
explain() {
  local diag
  diag=$(diagnose "$2")
  jq -c --arg error "$(error_line "$2")" --argjson diag "${diag:-null}" '
    {job: (.name // ""), step: ([.steps // [] | .[] | select(.conclusion == "failure") | .name] | first // ""),
     error: $error, diagnosis: $diag, url: (.html_url // "")}' <<<"$1"
}
