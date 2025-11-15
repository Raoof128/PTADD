## Description

<!-- Provide a clear and concise description of your changes and the motivation behind them -->

## Type of Change

<!-- Please check the relevant option(s) -->

- [ ] 🚀 New attack technique
- [ ] 🔍 Detection rule improvement
- [ ] 🛡️ Hardening enhancement
- [ ] 📝 Documentation update
- [ ] 🐛 Bug fix
- [ ] 🏗️ Infrastructure improvement
- [ ] 🧪 Testing/validation enhancement
- [ ] ♻️ Refactoring (no functional changes)

## MITRE ATT&CK Mapping

<!-- If applicable, provide MITRE ATT&CK details -->

- **Technique ID**: [e.g., T1558.005]
- **Technique Name**: [e.g., Kerberos Delegation Attacks]
- **Tactic**: [e.g., Credential Access, Lateral Movement]

**If not applicable, write:** N/A

## Changes Made

<!-- Provide a detailed list of what you changed -->

- Added/modified/removed...
- Updated...
- Fixed...

## Testing Performed

<!-- Detail the testing you've done to validate your changes -->

### Validation Checks

- [ ] Python syntax validation passed (`python3 -m py_compile`)
- [ ] PowerShell syntax validation passed (if applicable)
- [ ] YAML syntax validation passed (if applicable)
- [ ] `./lab-setup/validate-lab.sh` passed with 0 errors
- [ ] Lab deployment successful
- [ ] Manual testing completed

### Attack Testing (if applicable)

- [ ] Attack script executes successfully
- [ ] Attack produces expected output
- [ ] Credentials and parameters work as documented
- [ ] Error handling works correctly (tested with invalid inputs)
- [ ] Cleanup/logging works as expected

### Detection Testing (if applicable)

- [ ] Detection rules trigger on attack execution
- [ ] Alert appears in Wazuh dashboard
- [ ] False positive testing completed (minimum 24-hour baseline)
- [ ] Detection time is acceptable (<30 seconds)
- [ ] Alert severity is appropriate

### Documentation Testing

- [ ] Documentation is clear and accurate
- [ ] All links work correctly
- [ ] Code examples are tested and functional
- [ ] Markdown renders correctly

## Detection Coverage

<!-- If you added/modified detection rules, provide metrics -->

- **Primary Detection Method**: [e.g., Event ID 4769 with delegation flags]
- **Secondary Detection**: [e.g., Event ID 4624 from service account]
- **Coverage Rate**: [e.g., 94%]
- **False Positive Rate**: [e.g., 0.8%]
- **Mean Time to Detection**: [e.g., 6.2 seconds]

**If not applicable, write:** N/A

## Breaking Changes

<!-- Do your changes break backward compatibility? -->

- [ ] Yes, this PR introduces breaking changes
- [ ] No, this is backward compatible

<!-- If yes, describe the breaking changes and migration path -->

**Breaking Changes Details:**

## Checklist

<!-- Please check all that apply -->

### Code Quality

- [ ] Code follows project coding standards (see CONTRIBUTING.md)
- [ ] Comments and docstrings added/updated
- [ ] Type hints used (Python) or parameter validation (PowerShell)
- [ ] Error handling implemented properly
- [ ] Logging configured for attack activities
- [ ] No sensitive data committed (credentials, keys, real IPs)

### Documentation

- [ ] README.md updated (if needed)
- [ ] ATTACK_PLAYBOOK.md updated (for new attacks)
- [ ] DETECTION_MATRIX.md updated (for new detections)
- [ ] CHANGELOG.md updated
- [ ] Code comments explain "why" not just "what"
- [ ] All new files have header comments with purpose and MITRE mapping

### Security

- [ ] No real credentials or API keys committed
- [ ] `.gitignore` updated for new sensitive file types (if needed)
- [ ] Attack output files excluded from commits
- [ ] Changes follow ethical security research guidelines
- [ ] Legal compliance considered (see CODE_OF_CONDUCT.md)

### Files Changed

<!-- List the main files you've changed -->

```
attack-scripts/new_attack.py
attack-scripts/new_attack.ps1
detection-rules/sigma-rules/new_detection.yml
documentation/ATTACK_PLAYBOOK.md
documentation/DETECTION_MATRIX.md
CHANGELOG.md
```

## Screenshots

<!-- Optional: Add screenshots of detection alerts, attack output, dashboard, etc. -->

<!-- Example:
![Detection Alert](url-to-screenshot)
![Attack Output](url-to-screenshot)
-->

## Additional Context

<!-- Any additional information that reviewers should know -->

## Reviewer Notes

<!-- Specific areas where you'd like reviewer focus -->

- Please pay special attention to...
- I'm unsure about...
- Alternative approaches considered...

---

## For Maintainers

<!-- Maintainers will fill this out during review -->

### Review Checklist

- [ ] Code quality meets standards
- [ ] Testing is thorough
- [ ] Documentation is complete
- [ ] No security concerns
- [ ] CHANGELOG.md entry is appropriate
- [ ] Ready to merge

### Post-Merge Actions

- [ ] Update project metrics
- [ ] Announce in Discussions (if significant feature)
- [ ] Update documentation index
- [ ] Tag version (if release)
