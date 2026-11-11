"""Read-only GitHub access through the `gh` CLI and the login you already have.

Only GET requests are made. A 403 or 404 comes back as None ("couldn't see it"),
never as "it isn't there", so a narrowly scoped token produces fewer findings
instead of false ones.
"""

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

# gh prints these when a token works in general but the org enforces SAML SSO.
SAML_HINTS = ("saml enforcement", "saml sso", "organization saml")


class GitHubError(Exception):
    def __init__(self, message, kind="error"):
        super().__init__(message)
        self.kind = kind  # "auth", "saml", "rate_limit", "missing_cli", "error"


class GitHub:
    def __init__(self, runner, org):
        self.runner = runner
        self.org = org

    def _get(self, path, raw=False, timeout=30):
        args = ["gh", "api", "--method", "GET"]
        if raw:
            args += ["-H", "Accept: application/vnd.github.raw"]
        args.append(path)
        r = self.runner.run(args, timeout=timeout)
        if r.code == 127:
            raise GitHubError("The gh CLI is not on PATH", "missing_cli")
        if r.ok:
            return r.stdout if raw else json.loads(r.stdout or "null")
        text = r.output.lower()
        if any(h in text for h in SAML_HINTS):
            raise GitHubError(r.output.strip()[:300], "saml")
        if "rate limit" in text:
            raise GitHubError(r.output.strip()[:300], "rate_limit")
        if "http 401" in text or "bad credentials" in text or "gh auth login" in text:
            raise GitHubError(r.output.strip()[:300], "auth")
        if "http 403" in text or "http 404" in text:
            return None
        raise GitHubError(r.output.strip()[:300])

    def check_access(self):
        """Raise GitHubError if we can't read the org at all."""
        if self._get(f"orgs/{quote(self.org)}") is None:
            # Not visible as an org: may be a user account. Try that before failing.
            if self._get(f"users/{quote(self.org)}") is None:
                raise GitHubError(f"Can't see '{self.org}' on GitHub with this token", "auth")

    def repo(self, name):
        return self._get(f"repos/{quote(self.org)}/{quote(name)}")

    def runs(self, name, days, limit):
        since = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%d")
        out, page = [], 1
        while len(out) < limit:
            data = self._get(
                f"repos/{quote(self.org)}/{quote(name)}/actions/runs"
                f"?per_page=100&page={page}&created=%3E%3D{since}&exclude_pull_requests=true"
            )
            if data is None:
                return None if page == 1 else out
            batch = data.get("workflow_runs", [])
            out += batch
            if len(batch) < 100:
                break
            page += 1
        return out[:limit]

    def jobs(self, name, run_id):
        data = self._get(f"repos/{quote(self.org)}/{quote(name)}/actions/runs/{int(run_id)}/jobs?per_page=100")
        return None if data is None else data.get("jobs", [])

    def job_log(self, name, job_id):
        """Logs expire and can be large. A failed fetch means no log, not a failed sweep."""
        try:
            return self._get(
                f"repos/{quote(self.org)}/{quote(name)}/actions/jobs/{int(job_id)}/logs", raw=True, timeout=60
            )
        except GitHubError as err:
            if err.kind != "error":
                raise
            return None

    def workflow_files(self, name):
        """Return {path: text} for .github/workflows, or None if we can't see them."""
        listing = self._get(f"repos/{quote(self.org)}/{quote(name)}/contents/.github/workflows")
        if listing is None:
            return None
        files = {}
        for item in listing:
            if item.get("type") == "file" and item["name"].endswith((".yml", ".yaml")):
                text = self._get(f"repos/{quote(self.org)}/{quote(name)}/contents/{quote(item['path'])}", raw=True)
                if text is not None:
                    files[item["path"]] = text
        return files
