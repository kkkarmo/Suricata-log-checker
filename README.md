echo "# Suricata Analyzer

This project provides a Docker container that analyzes Suricata logs using AI.

## Files

- \`Dockerfile\`: Defines the Docker image for the Suricata analyzer
- \`docker-compose.yml\`: Defines the service for easy deployment
- \`suricata_analyzer.py\`: The main Python script for analyzing Suricata logs
- \`requirements.txt\`: Lists the Python dependencies

## Usage

1. Clone this repository
2. Create a \`.env\` file with your GROQ API key:
   \`\`\`
   GROQ_API_KEY=your_api_key_here
   \`\`\`
3. Run \`docker-compose up -d\`

For more details, see the Docker image at [ghcr.io/kkkarmo/suricata_analyzer](https://github.com/kkkarmo/suricata-analyzer/pkgs/container/suricata_analyzer)
" > README.md

git add README.md
