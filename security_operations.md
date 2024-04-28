# Security Operations

## 1.1 Explain the importance of system and network architecture concepts in Security operations.

### Log Ingestion
- **Log ingestion**: Aggregate of formatted logs from various resources.
- **Time synchronization**: Synchronization of all logs to give a history of actions.
- **Logging levels**: Assign level of importance to logs and, categorization of logs for delegation to specific teams.

### Operating system (OS) concepts
- **Windows Registry**: A hierarchical database. Stores low-level settings for the Microsoft Windows OS and, any apps that use the registry. The kernel, device drivers, services, Security Accounts Manager, and user interfaces may use the registry.
- **System Hardening**: Reducing security risks via Updates/Patches, User access management, Network access controls, monitoring and detection (anti-virus and anti-malware, IDS, IPS), encryption(data, apps, network)
- **File Structure**: The way files are organized on a system.

### Configuration file locations
- **System processes**: Instance of a computer program executed through threads.
- **Hardware architecture**: Design of the physical components and connections of a system.

### Infrastructure Concepts
- **Serverless**: Build and run services without having to manage the underlying infrastructure. Cloud computing - The provider handles machine resources.
- **Virtualization**: Virtual representations of servers, storage, networks, physical machines, etc.
- **Containerization**: Deployment process. Type of virtualization that combines all components of the application into a single container image.

### Network Architecture
- **On-premises**: Using private data centers. Hardware, Software, Data, and Metrics are all controlled by the owner(s).
- **Cloud**: Distributed collection of servers that host software and infrastructure. Resources become available on demand. Users have no ability to manage.
- **Hybrid**: Combo of different types of architectures
- **Network Segmentation**: Separating a network into smaller subnets, and each subnet can be assigned its own controls.
- **Zero Trust**: Users will be authenticated, authorized, and validated continuously. No one is trusted by default. Assumes no trad network edge.
- **Secure Access Secure Edge (SASE)**: Cloud-based architecture. Combines network and security functions into one server. Controls are directly to source of connection.
- **Software-defined Networking (SDN)**: Type of Segmentation. Separates control from forwarding.

### Identity and Access Management(IAM)
- **Multifactor Authentication (MFA)**: IAM Policy. Requires "Something you have", "Something you know", or "Something you are" in additions to username/password.
- **Single Sign-on (SSO)**: User logs in once via single ID, and has access to other independent system.
- **Federation**: Trust policy. Organizations agree to policies for the sharing of information.
- **Privileged Access Management (PAM)**: Strategy for control and protection of privileged accounts. PAM identifies users, systems, and apps that need privileged access then grants the least privilege possible for them to function normally.
- **Passwordless**: Sign on method that replaces the use of passwords.
- **Cloud Access Security Broker (CASB)**: Provides security policy enforcement between the service provider and customer.

##$ Encryption
- **Public Key Infrastructure (PKI)**: Policies/hardware/software that manage digital certs(Create, manage, distribute, use, store, and revoke), and public-key encryption. Public(Encrypts) and Private(Decrypts) Keys.
- **Secure Sockets Layer (SSL) Inspection**: Monitoring encrypted traffic.

### Sensitive data protection:
- **Data Loss Prevention (DLP)**: Identify data loss, leakage, or misuse of data using tools/procedures.
- **Personally Identifiable: Information (PII)**: Any info that can be used to identify an individual(name, address, SSN, etc)
- **Cardholder Data (CHD)**: PII tied to a debt/credit card.


## 1.2 Given a scenario, analyze indicators of potentially malicious activity.
Network-related
- **Bandwidth Consumption**: Data being used. Measured in bits per sec or Kbps
- **Beaconing**: Constant communication between two systems.
- **Irregular Peer-to-Peer Communication**: Atypical traffic patterns, which can be an indicator of malicious activity e.g data theft, malware
- **Rogue devices on the network**: Unauthorized device
- **Scans/Sweeps**: Detection. Port, Network, and Vulnerability.
- **Unusual Traffic Spikes**: Deviates from normal traffic patterns. Potential IoC
- **Activity on unexpected ports**: Atypical traffic from ports. Potential IoC

### Host-Related
- **Processor Consumption**: Load placed on the processor's core during data processing.
- **Memory Consumption**: Memory allocated to processes.
- **Drive Capacity Consumption**: Storage capacity - HDD/SSD usage
- **Unauthorized Software**: Unauthorized installed software
- **Malicious Processes**: Processes that cause harm
- **Unauthorized Changes**:
- **Unauthorized Privileges**:
- **Data exfiltration**: Unauthorized removal of data
- Abnormal OS process behavior: Activity outside of the normal baseline.
- File system changes or anomalies:
- Registry changes or anomalies: Activity outside of the normal baseline.
- Unauthorized scheduled tasks:

### Application-related
- **Anomalous activity**: Activity outside of the normal baseline.
- **Introduction of new accounts**:


## 1.3 Given a scenario, use appropriate tools or techniques to determine malicious activity

### Tools
- **Wireshark**: Used to analyze network traffic by intercepting and displaying packets that are being created or received by the computer. pcap logs.
- **tcpdump**: Used to analyze network traffic by intercepting and displaying packets that are being created or received by the computer.
- **Log analysis/correlation**: Looking for patterns in activity that may be related to others.

- **Security information and event management (SIEM)**: Aggregate of log data from multiple sources(network, servers, security devices). **Security Info Management(SIM)** and **Security Event Management(SEM)** combined

- **:Security Orchestration, Automation, and Response (SOAR)**: Tech stack that allow for automated response to certain incidents. Removes the potential need for manual action.

### Endpoint Security
- **Endpoint Detection and Response (EDR)**: Endpoint monitoring. EDR can be used for Detection, Investigation, Threat hunting, and Response.
- **Domain Name Service (DNS) Reputation**: Poor reputation may lead to resolvers(Quad9, Neustar) being blocked.
- **Internet Protocol (IP) Reputation**: Amount of trust associated to a specific IP
- **WHOIS**: Data lookup tool. Contains information on DNS, Domain names, name servers, IPs.
- **AbuseIPDB**: Site to report IPs performing malicious activities
- **File analysis**: Looking at meta data and content
- Strings: Sequence of symbols that is interpreted to represent a precise meaning

- VirusTotal: Site that checks files and urls

### Sandbox
- **Sandboxing**: An isolated environment that allows for program exeuction without risking the entire system.
- **Joe Sandbox**: Cloud Sandbox provider
- **Cuckoo Sandbox**: Open source automated malware analysis system.


### Common techniques
- **Pattern recognition**: Algo that looks for patterns and regularities in data
- **Command and control**: Chain of command. Determines authority.
- **Interpreting suspicious commands**: sudo, chmod. Access and manipulation of passwd or shadow file.
- **Email analysis**: Turn headers into a human readable format.
- **Header fields**: List of strings received by client and server on http requests. Invis to end-user and logged by server and client app.
- **Impersonation**: Telling a system you're a different user.
- **DomainKeys Identified Mail (DKIM)**: Email auth method using digital sig that verifies an email was send by the actual owner. Helps detect forged email address from senders.
- **Domain-based Message Authentication, Reporting, and Conformance (DMARC)**: Email security protocol. Helps protect email senders from data breaches.


## 1.4 Compare and contrast threat-intelligence and threat-hunting concepts.

### Threat actors
- **Advanced Persistent Threat (APT)**: Attacks that maintains unauthorized access to a network usually for data theft. A sophisticated attack, which may be backed by nation states.
- **Hacktivists**: Actors with a politic agenda or want social change.
- **Organized Crime**: Actors whose goal is profit.
- **Nation-State**: Government sanctioned hackers. Provided resources by their gov.
- **Script kiddie**: An actor who runs scripts, but doesn't understand how they work. Scripts are bought or found.
- **Insider threat**: Employee within the org itself

- Supply chain: Sequence of processes involved in production
• Tactics, techniques, and procedures (TTP): behaviors, actions, and strategies used to develop cyberattacks.
• **Confidence Levels**:
- Timeliness
- Relevancy
- Accuracy
• Collection methods and sources
- Open source: Publicly accessible allowing for anyone to make changes
o Social media: OSINT
o Blogs/forums: OSINT
o Government bulletins
o **Computer emergency response team (CERT)**: Protects and manages an orgs Cybersecurity.
o **Cybersecurity incident response team (CSIRT)**: Documents and responds to incidents.
o Deep/Dark Web: Unindexed portion of the web, not accessible by search engines.
- Closed source: Proprietary code
- Paid feeds: Aggregate sites that require money
- Information sharing organizations
- Internal sources: Funds that a business generates from within itself.

## 1.5 Explain the importance of efficiency and process improvement in security operations.

### Standardize Processes
- Identification of tasks suitable for automation
- Repeatable/do not require human interaction
- Minimize human engagement
- Team coordination to manage and facilitate automation
- **Data enrichment**: Improving raw data by combining data from internal and external sources
- **Application programming interface (API)**: How two pieces of software communication with each other. Get, Post, etc..
- **Webhooks**: User-defined http callback. Communicate the occurrence of events from a system to another system.
- **Plugins**: Software components that add additional specific functionalities to an existing app or site.
• **Single pane of glass**: Management console that aggregates data from multiple sources displays it in a single display
