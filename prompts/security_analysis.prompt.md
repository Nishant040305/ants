Analyze this HTTP network request for security and privacy concerns.

Request Details:
- Method: {method}
- URI: {uri}
- Source IP: {src_ip}
- Destination IP: {dst_ip}
- Headers: {headers}
- Body: {body}

Analyze for potential issues:
1. Data exposure risks (API tokens, authentication data)
2. Security best practices compliance
3. Unusual request patterns
4. Privacy considerations

Return your analysis in this exact JSON format:
{{
    "severity": <number 0-10>,
    "risk_level": <"low"|"medium"|"high"|"critical">,
    "findings": [<list of specific security findings>],
    "recommendations": [<list of recommendations>],
    "sensitive_data_detected": <boolean>,
    "explanation": <detailed explanation>
}}

Guidelines:
- Be specific about detected sensitive information
- Provide actionable security recommendations
- Score severity based on potential impact
- Consider both immediate and long-term risks