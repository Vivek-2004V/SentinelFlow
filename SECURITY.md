# Security Policy

## Security Boundary

SentinelFlow is designed as a passive network intelligence system.

The system:

- does not probe monitored hosts
- does not initiate network handshakes
- does not decrypt application payloads
- does not perform inline blocking
- does not send mitigation commands
- does not provide a response path to the monitored network

Its operational output is alert-only.

## Responsible Testing

Only authorized, isolated laboratory traffic should be used for attack simulation.

Do not use SentinelFlow traffic-generation or testing workflows against systems you do not own or have explicit authorization to test.

## Reporting

Please report security vulnerabilities privately to the project maintainers before public disclosure.
