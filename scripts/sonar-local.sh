#!/usr/bin/env bash
# Local SonarQube analysis for this Rust and React project.
# Starts an ephemeral SonarQube Community container, runs scripts/verify.sh
# coverage, analyses the project with the pull-request workflow's scope using the
# local sonar-scanner, and fails unless the quality gate passes and no open issue
# touches a line changed since the base branch (committed or not). An issue
# touches a changed line when its own range or any secondary location, in any
# file, covers it, so a finding already present in a changed method counts too.
# When the base branch does not exist, every open issue counts.
# Prereqs: docker, sonar-scanner, cargo, node, curl, python3, git, openssl
# Usage: ./scripts/sonar-local.sh   (BASE_BRANCH defaults to origin/main)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

for tool in docker sonar-scanner cargo node curl python3 git openssl; do
    command -v "${tool}" >/dev/null || { echo "ERROR: ${tool} is required." >&2; exit 1; }
done

SONAR_PORT="${SONAR_PORT:-9000}"
BASE_BRANCH="${BASE_BRANCH:-origin/main}"
CONTAINER_NAME="identity-manager-sonarqube-${SONAR_PORT}"
SONAR_URL="http://127.0.0.1:${SONAR_PORT}"
QG_NAME="local-overall"

SCANNER_DIR="$(mktemp -d)"
PROJECT_KEY="identity-manager"

cleanup() {
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    rm -rf "${SCANNER_DIR}"
}
trap cleanup EXIT

api() {
    curl -sf -u "${SONAR_CREDS}" "$@"
}

json() {
    local expression="$1"
    python3 -c "import json, sys; d = json.load(sys.stdin); print(${expression})"
}

# Prints every page of open issues, one JSON document per line.
issue_pages() {
    local page=1 body
    while :; do
        body=$(api "${SONAR_URL}/api/issues/search?componentKeys=${PROJECT_KEY}&resolved=false&ps=500&p=${page}" \
            | json "json.dumps(d)")
        echo "${body}"
        if [[ "$(echo "${body}" | json "d['paging']['pageIndex'] * d['paging']['pageSize'] >= d['paging']['total']")" == "True" ]]; then
            return
        fi
        page=$((page + 1))
    done
}

cleanup
echo "Starting SonarQube Community on port ${SONAR_PORT}..."
docker run -d --name "${CONTAINER_NAME}" -p "127.0.0.1:${SONAR_PORT}:9000" sonarqube:community >/dev/null

for i in $(seq 1 120); do
    if curl -sf "${SONAR_URL}/api/system/status" 2>/dev/null | grep -q '"status":"UP"'; then
        break
    fi
    if [[ "$i" -eq 120 ]]; then
        echo "ERROR: SonarQube did not start within 2 minutes." >&2
        exit 1
    fi
    sleep 1
done

# The container is ephemeral; its admin password is generated per run and dies with it.
ADMIN_PASSWORD="$(openssl rand -hex 12)Aa1!"
curl -sf -o /dev/null -u admin:admin -X POST \
    "${SONAR_URL}/api/users/change_password?login=admin&previousPassword=admin&password=${ADMIN_PASSWORD}"
SONAR_CREDS="admin:${ADMIN_PASSWORD}"
TOKEN=$(api -X POST "${SONAR_URL}/api/user_tokens/generate?name=local-$(date +%s)" | json "d['token']")

echo "Configuring quality gate '${QG_NAME}' (ratings A, hotspots reviewed, coverage >= 80%, duplication <= 3%)..."
api -o /dev/null -X POST "${SONAR_URL}/api/qualitygates/create?name=${QG_NAME}"
for CONDITION in \
    "metric=reliability_rating&op=GT&error=1" \
    "metric=security_rating&op=GT&error=1" \
    "metric=sqale_rating&op=GT&error=1" \
    "metric=security_hotspots_reviewed&op=LT&error=100" \
    "metric=coverage&op=LT&error=80" \
    "metric=duplicated_lines_density&op=GT&error=3"; do
    api -o /dev/null -X POST "${SONAR_URL}/api/qualitygates/create_condition?gateName=${QG_NAME}&${CONDITION}"
done
api -o /dev/null -X POST "${SONAR_URL}/api/qualitygates/set_as_default?name=${QG_NAME}"

echo "Running the coverage build..."
bash scripts/verify.sh coverage

echo "Running the Sonar scanner..."
# Scope arguments match .github/workflows/sonar.yml.
sonar-scanner \
    -Dproject.settings=/dev/null \
    "-Dsonar.working.directory=${SCANNER_DIR}" \
    "-Dsonar.host.url=${SONAR_URL}" \
    "-Dsonar.token=${TOKEN}" \
    "-Dsonar.projectKey=${PROJECT_KEY}" \
    -Dsonar.sources=. \
    -Dsonar.tests=crates,app/src \
    "-Dsonar.test.inclusions=crates/**/tests/**,app/src/**/*.spec.ts,app/src/**/*.spec.tsx" \
    "-Dsonar.exclusions=**/target/**,**/node_modules/**,**/dist/**,reports/**,app/coverage-vitest/**,crates/**/tests/**,app/src/**/*.spec.ts,app/src/**/*.spec.tsx" \
    "-Dsonar.coverage.exclusions=app/src/main.tsx,app/*.config.ts,scripts/**" \
    -Dsonar.rust.lcov.reportPaths=reports/rust.lcov \
    -Dsonar.rust.clippyReport.reportPaths=reports/clippy.json \
    -Dsonar.javascript.lcov.reportPaths=reports/ui.lcov

CE_TASK_ID=$(grep '^ceTaskId=' "${SCANNER_DIR}/report-task.txt" | cut -d= -f2-)

for i in $(seq 1 60); do
    CE_STATUS=$(api "${SONAR_URL}/api/ce/task?id=${CE_TASK_ID}" | json "d['task']['status']")
    case "${CE_STATUS}" in
        SUCCESS) break ;;
        FAILED|CANCELED) echo "ERROR: analysis task ${CE_STATUS}." >&2; exit 1 ;;
        *) ;; # PENDING or IN_PROGRESS: keep waiting
    esac
    if [[ "$i" -eq 60 ]]; then
        echo "ERROR: analysis did not finish within 2 minutes." >&2
        exit 1
    fi
    sleep 2
done

echo ""
echo "Files known to Sonar and coverage per language:"
api "${SONAR_URL}/api/measures/component_tree?component=${PROJECT_KEY}&qualifiers=FIL&metricKeys=lines_to_cover,uncovered_lines&ps=500" | python3 -c "
import json, sys
stats = {}
for c in json.load(sys.stdin)['components']:
    m = {x['metric']: int(x['value']) for x in c['measures']}
    files, to_cover, uncovered = stats.get(c.get('language', 'none'), (0, 0, 0))
    stats[c.get('language', 'none')] = (files + 1, to_cover + m.get('lines_to_cover', 0), uncovered + m.get('uncovered_lines', 0))
for lang, (files, to_cover, uncovered) in sorted(stats.items()):
    coverage = f'{100 * (to_cover - uncovered) / to_cover:.1f} %' if to_cover else 'n/a'
    print(f'  {lang}: {files} files, coverage {coverage}')
"
DUPLICATION=$(api "${SONAR_URL}/api/measures/component?component=${PROJECT_KEY}&metricKeys=duplicated_lines_density" \
    | json "d['component']['measures'][0]['value'] if d['component']['measures'] else 'n/a'")
echo "Duplication: ${DUPLICATION} %"
echo ""
echo "Quality gate:"
GATE_STATUS=$(api "${SONAR_URL}/api/qualitygates/project_status?projectKey=${PROJECT_KEY}" | python3 -c "
import json, sys
status = json.load(sys.stdin)['projectStatus']
for c in status.get('conditions', []):
    print(f\"  {c['metricKey']}: {c.get('actualValue', 'N/A')} (threshold {c.get('errorThreshold', 'N/A')}) - {c['status']}\", file=sys.stderr)
print(status['status'])
")
echo "  Status: ${GATE_STATUS}"

MERGE_BASE=""
if git rev-parse --verify --quiet "${BASE_BRANCH}^{commit}" >/dev/null; then
    MERGE_BASE=$(git merge-base "${BASE_BRANCH}" HEAD)
fi
echo ""
echo "Open issues touching lines changed since ${BASE_BRANCH}:"
CHANGED_ISSUES=$(issue_pages | MERGE_BASE="${MERGE_BASE}" python3 -c "
import json, os, re, subprocess, sys

merge_base = os.environ['MERGE_BASE']
diff = subprocess.run(['git', 'diff', '-U0', merge_base], capture_output=True, text=True, check=True) if merge_base else None
changed, current = {}, None
for line in (diff.stdout.splitlines() if diff else []):
    if line.startswith('+++ '):
        current = line[6:] if line.startswith('+++ b/') else None
    elif line.startswith('@@') and current:
        start, count = re.search(r'\+(\d+)(?:,(\d+))?', line).groups()
        changed.setdefault(current, set()).update(range(int(start), int(start) + int(count or 1)))
untracked = subprocess.run(['git', 'ls-files', '-z', '--others', '--exclude-standard'], capture_output=True, text=True, check=True)
for path in filter(None, untracked.stdout.split('\0')):
    changed[path] = None

def touches(location):
    path = location['component'].split(':', 1)[-1]
    if merge_base and path not in changed:
        return False
    if not merge_base:
        return True
    lines, text_range = changed[path], location.get('textRange')
    if lines is None or text_range is None:
        return True
    return any(number in lines for number in range(text_range['startLine'], text_range['endLine'] + 1))

count = 0
for issue in (issue for page in sys.stdin for issue in json.loads(page)['issues']):
    locations = [issue] + [loc for flow in issue.get('flows', []) for loc in flow.get('locations', [])]
    if any(touches(loc) for loc in locations if 'component' in loc):
        count += 1
        path = issue['component'].split(':', 1)[-1]
        print(f\"  {issue['rule']} {path}:{issue.get('line') or '-'} - {issue['message']}\", file=sys.stderr)
print(count)
")
echo "  Total: ${CHANGED_ISSUES}"

if [[ "${GATE_STATUS}" != "OK" || "${CHANGED_ISSUES}" != "0" ]]; then
    echo ""
    echo "FAILED: quality gate ${GATE_STATUS}, ${CHANGED_ISSUES} open issue(s) touching changed lines."
    exit 1
fi
echo ""
echo "PASSED"
