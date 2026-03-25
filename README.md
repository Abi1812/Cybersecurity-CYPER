CYPER Cybersecurity Defense(Scanning) system:

A local tool that scans your device for unsecure connections annd potential risks, then provides a findings report based on this information

Overview of the project:

CYPER performs automated checks on 4 key areas which are running processes, network exposure, authentication logs and filesystem permissions. Results provided, are the key security information and is provided as an output in the form of either, human-readable  text or JSON. 

The project is built using Python with no compulsory dependencies needed, however, (psutil) is used if it is available.

Installation Guide:

Pre-Installation Requirements: Python 3.10 or newer versions

Step 1: Clone he reposistory using the command: git clone https://github.com/Abi1812/Cybersecurity-CYPER.git 

Step 2(Optional): Install psutil dependency for a better scanning proceess and better results.

How to use:

Option 1 (Not recommended): To a get standard text report in your terminal as an output run the command: python3 defender.py 

Option 2 (Recommended): To get a thorough scan standard and a text report in your terminal as an output run the command: sudo python3 defender.py
To receive your output in JSON, run the same commands but with "--json" at the back of the command. Eg. python3 defender.py --json/sudo python3 defender.py --json

If you would like to save the output as a file, you may give the same commands but with "--out filename.txt" at the back of the command. Eg. python3 defender.py --out filename.txt/sudo python3 defender.py --out filename.txt

How does the project work?

- collect.py gathers system data from 4 different modules which are processes, auth logs, network listeners and filesystem permissions. Each module degrades in a graceful manner if the access to the data is denied or the data is unavailable, logging a coverage note instead of failing and crashing
- rules.py evaluates the collected data according to the security procedures, Finding severity, details and potential remediation efforts of the objects
- report.py renders the findings by sorting them according to severity as formatted text in the output section or as JSON text
- defender.py is the entry point which handles the routing of the outputs and CLI arguments if any

What are the checks performed by the software?

- Public listeners on risky ports such as SSH
- High quantity of public listeners
- Passwordless sudo entries 
- Brute force login attempts

What would an output potentially look like?

Cybersecurity Defense System by CYPER Report
============================================================
Total findings: 1
============================================================

Findings
------------------------------------------------------------
[MEDIUM] Many public listening ports
  ID: MANY_PUBLIC_LISTENERS
  Detail: Many services listening on public interfaces, increasing attack surface.
  Evidence: {"count": 10}
  Remediation: Disable unused services and restrict bind addresses to localhost where possible
  Tags: network, exposure

============================================================