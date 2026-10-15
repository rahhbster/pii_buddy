---
name: Missed PII Report
about: Report PII that wasn't detected or redacted
title: "[MISSED] "
labels: detection-quality
---

## What was missed?

<!-- Describe the type of PII that wasn't detected. Do NOT paste actual PII here. -->
<!-- Example: "A person's name in a non-Western format was not redacted" -->



## PII Type

- [ ] Name (person)
- [ ] Email address
- [ ] Phone number
- [ ] Street address
- [ ] Date of birth
- [ ] SSN / National ID
- [ ] URL
- [ ] Other: ___________

## Document Type

- [ ] Resume / CV
- [ ] Interview transcript
- [ ] General text
- [ ] Other: ___________

## Why do you think it was missed?

<!-- Help us understand the pattern. Examples: -->
<!-- - "Name was in a non-Western format (e.g., surname first)" -->
<!-- - "Phone number used international format with country code" -->
<!-- - "Date was in DD/MM/YYYY format" -->



## Redacted Output (safe to paste)

<!-- You can paste the REDACTED output here — it only contains tags like <NAME XX>, <<EMAIL_1>>, etc. -->
<!-- This helps us see the context around the missed item. -->

```
(paste redacted output here)
```

## PII Buddy Version

<!-- Installed from a release: the release tag you downloaded. Cloned the repo: run `git rev-parse --short HEAD` in the pii_buddy folder. -->

## Additional Context

<!-- Anything else that might help us improve detection -->
