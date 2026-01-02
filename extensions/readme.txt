# Basic domain reconnaissance
./recon-sentinel.sh example.com

# Full scan with report (display only)
./recon-sentinel.sh -r example.com

# Export report to file
./recon-sentinel.sh -r -e report.txt example.com

# Verbose mode with increased parallelism
./recon-sentinel.sh -v -j 20 example.com

# IP address scan
./recon-sentinel.sh 192.168.1.1

# CIDR range scan
./recon-sentinel.sh 192.168.1.0/24

# HTTP-only analysis (quick web check)
./recon-sentinel.sh --http-only https://example.com

# Ports only (fastest mode)
./recon-sentinel.sh --ports-only 10.10.10.10

# Skip subdomain enumeration (for IPs or speed)
./recon-sentinel.sh --no-subs example.com

# Stealth mode (slower, more careful)
./recon-sentinel.sh -s example.com
