# Dependabot Alerts Example

This example shows how to triage GitHub Dependabot alerts with depquiet.

## Export your alerts

```bash
gh api /repos/OWNER/REPO/dependabot/alerts --paginate > alerts.json
```

## Run depquiet

```bash
cat alerts.json | depquiet --stdin
```

## What happens

The sample `alerts.json` contains 4 alerts:

| Alert | Package | Severity | State | depquiet verdict |
|---|---|---|---|---|
| CVE-2020-8203 | lodash | high | open | FILTERED (community template) |
| CVE-2022-25883 | semver | moderate | open | FILTERED (devDependency + template) |
| CVE-2024-4068 | braces | high | open | ACTION |
| CVE-2017-16137 | debug | low | dismissed | skipped (not open) |

- **lodash** and **semver** are filtered by built-in community templates
- **semver** is also a devDependency (scope: development)
- **braces** has no template match and high severity — needs action
- **debug** is dismissed in GitHub, so depquiet skips it entirely

depquiet processes only open alerts — dismissed and fixed alerts are excluded.
