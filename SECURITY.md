# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Email the maintainers with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Security Considerations

### API Keys and Credentials

- Never commit AWS credentials, API keys, or secrets to the repository.
- Use environment variables or AWS IAM roles for authentication.
- The tool reads AWS credentials from the standard SDK chain (`AWS_ACCESS_KEY_ID`, `~/.aws/credentials`, instance profiles).

### AI Model Access

- AI analysis requires Amazon Bedrock access with permissions for `bedrock:InvokeModel`.
- Model invocations send CloudFormation template snippets and finding summaries to the configured Bedrock model. Do not analyze templates containing embedded secrets.

### Template Content

- Templates are parsed locally. No template content is sent externally unless AI analysis is enabled.
- With `--no-ai`, all analysis is fully local and deterministic.

### Policy-as-Code

- Policy files should be version-controlled and reviewed like application code.
- Policy decisions override the deterministic risk engine — review policies carefully before deploying to production CI/CD.

### Dependencies

- Run `pip audit` or `safety check` regularly to scan for known vulnerabilities in dependencies.
- Pin dependency versions in production deployments.
