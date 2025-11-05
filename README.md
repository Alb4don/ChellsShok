# Disclaimer

> ***Use only on systems you own or have explicit permission to test.
  Obtain written authorization
  Limit scope***

# Installation

      git clone https://github.com/Alb4don/ChellsShok.git
      
      cd ChellsShok

      pip install -r requirements.txt

# Usage

- Basic Scan

      python shellshock_scann.py http://target.com/cgi-bin/status.sh

- Advanced Options
  
      --timeout SECONDS,Request timeout (default: 15)
      --no-ssl-verify,Disable SSL verification (default)
      --method headers|params|post,Test specific vector(s)
      --verbose,Enable detailed output (default: on)

  ![front_01](https://github.com/user-attachments/assets/ab544302-4b7c-4251-b1b2-af3488fa599d)

  ![front_02](https://github.com/user-attachments/assets/02c0bad4-ca55-49b7-ae3a-0440e06f01af)

# Limitations And possible future improvements

- [ ] CGI Dependency,Only vulnerable if target uses Bash-based CGI scripts.
- [ ] False Negatives,Some servers strip or sanitize inputs before Bash.
- [ ] No Exploit Execution, Detects vulnerability does not run id, cat, etc.
- [ ] No Authentication Handling,Does not support login sessions or CSRF tokens.
