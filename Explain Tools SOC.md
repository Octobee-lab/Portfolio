
### Intrusion Detection System (IDS)

An Intrusion Detection System (IDS) is hardware or software used to detect security breaches and attacks by monitoring a network or host.

![[Pasted image 20250109144803.png]]

NIDS :  Détection anormale sur le Traffic réseau
HIDS: Détection anormale sur un hôte spécifique sur le réseau
PIDS: examine le trafic entre un serveur et un client d'une manière spécifique au protocole.
APIDS: détecter les failles de sécurité en surveillant la communication dans les protocoles spécifiques à l'application.
Hybrid  Detection : Utilise deux ou plus des ids cités 

Fonctions :

Détecter les failles et en avertir à l'administrateur ou envoyer au siem

Différents ids:
- **Zeek/Bro**
- **Snort**
- **Suricata**
- **Fail2Ban**
- **OSSEC**

The location of the IDS device in the network may vary depending on which type of IDS it is. For example, a NIDS-type device must pass all packets coming into the network over it. Therefore, it is more suitable to be positioned close to the network devices that provide access to the external network. A HIDS-type device, on the other hand, should be positioned close to the host in the network because it only examines the network packets coming to and leaving a certain host.

### Intrusion Prevention System (IPS)

An Intrusion Prevention System (IPS) is hardware or software that detects security violations by monitoring a network or host and prevents security violations by taking the necessary action

![[Pasted image 20250109151644.png]]

NIPS : detects security violations and eliminates security violations by monitoring all incoming traffic to the network it is in.

HIPS: monitors and analyzes suspicious activities for a host.

NBA : detects and blocks unusual traffic flows and Denial of Service (DoS) attacks on the network.

WIPS:  monitors and analyzes wireless network protocol traffic of wireless devices in a network.

Fonctions :
L'IPS est chargé de prévenir les comportements malveillants en détectant les failles de sécurité.

Ips :
- Cisco NGIPS
- Suricata
- Fidelis

The location of the IPS device in the network may vary depending on which type of IPS it is. In general terms, it should be placed at whatever point it needs to be located in the network due to its task.

### Firewall

A firewall is divided into many different types according to its features:

![[Pasted image 20250109152457.png]]

1 - are a type of firewall that functions at the application layer between two end systems. Unlike basic firewalls, it captures and analyzes packets in the application layer according to the OSI model. In this way, it works as an additional security measure on the application layer.

2-  These types of firewalls verify TCP connections and sessions and operate in the session layer of the OSI model.

3-  used when the institution receives firewall service over the cloud as a service. Another name is "FWaaS" (firewall-as-a-service)

4-Endpoint Firewalls are a type of host-based firewall installed on devices.

5-a type of firewall designed to access internet traffic and block unwanted connections. Such firewalls are used to hide the IP addresses in the internal network from the external network.

6-a type of firewall that combines the features of different firewalls available under the conditions of that day on a single firewall. These firewalls have a deep-packet inspection (DPI) feature. This type of firewall is designed to block external threats, malware attacks, and advanced attack methods.

7- the most basic type of firewall. It has a feature that monitors network traffic and filters incoming packets according to configured rules. A packet-Filtering firewall blocks the destination port if the incoming packet does not match the rule set

8-type of firewall capable of both packet inspection and TCP handshake verification

9-as all the features of an NGFW-type firewall. In addition, it has advanced threat detection features. Thanks to this feature, it can react quickly to attacks.

10- special type of stateful inspection firewalls with antivirus and intrusion prevention.


firewall rule is the part that is checked to decide whether to allow or block the passage of network packets coming to the firewall.


Quelques firewall:
- Fortinet
- Palo Alto Networks
- SonicWall
- Checkpoint
- Juniper
- pfsense
- Sophos

Firewall devices can be located in different places in the network according to their types.


### Endpoint Detection and Response (EDR)

Endpoint Detection and Response (EDR) is a security product that is installed on endpoint-qualified devices, constantly monitors the activities in the system, tries to detect security threats such as ransomware & malware, and takes action against malicious activities.

Function:
1. Monitoring and collecting each process on the device that may identify a security threat
2. Analyzing the behavior of threat actors according to the data collected on the device
3. Informing the relevant analyst by taking the appropriate security action against the threat actor obtained from the collected data.
4. Allow forensic analysis on the device to conduct in-depth investigation of suspicious activities

Quelques EDR:
- SentinelOne
- Crowdstrike
- CarbonBlack
- Palo Alto
- FireEye HX

### Antivirus Software (AV)

Antivirus Software (AV) is security software that detects malware on devices and blocks and removes malware from the system before it harms the device.

Antivirus software is generally responsible for scanning the system for security. Antivirus software can be divided into subtypes according to scanning methods:

Signature-Based Scanning:

In the signature-based scanning method, the antivirus software scans the system to detect malware with a digital signature, and if there is a matching signature, it marks the file it scans and matches as malicious and clears the file from the system. In this method, digital signatures are kept on the system in the database and must be constantly updated with up-to-date malware signatures. It is a method that has been used from the past to the present and is effective in detecting known malware. Although it does not catch every single malware, it can detect most of them.

The heuristic scanning method is a very different malware detection method than the previous signature-based scanning method. Instead of detecting by signature, it monitors the accesses and behaviors of the examined file. In this way, the probability of detecting malicious activities is much higher. For example, this behavior is flagged as suspicious if the executable file that the antivirus tracks is trying to read or modify a system file it shouldn't be able to access. Even if its signature is not in the antivirus database as malicious, it may be executable malware. This situation is logged by the antivirus.

Functions:
Détecter des malwares en scannat continuellement le système
Protèger contre les menaces externes
Nettoyer les systèmes de malware

Quelques anti-virus: 
- McAfee
- Symantec
- Bitdefender
- Eset
- Norton


### Sandbox Solutions

Sandbox is a technology used to run/open and examine executable files or file types with different extensions (pdf, docx, and xlsx, etc.) that are thought or known to be malware in an isolated environment. Thanks to the Sandbox, precautions are taken against the problems that may arise when the file is run/opened on a live system.


Sandbox de l'industrie :
- Checkpoint
- McAfee
- Symantec
- Trend Micro
- Proofpoint


### Data Loss Prevention (DLP)

Data Loss Prevention (DLP) is a technology that prevents sensitive and critical information from leaving the institution.

![[Pasted image 20250109160657.png]]

Network : Network DLP is responsible for taking security actions related to leaving critical and sensitive information on the network outside the organization. For example, the DLP product may block a connection that is attempted to upload a file to an FTP server, request it to be audited, or forward it as a log to the relevant security solution

Endpoint: The Endpoint DLP product is installed on the device and after installation, it manages suspicious activities on the device. Endpoint DLP is essential for protecting critical and sensitive information on the devices of remote personnel

Cloud: Cloud DLP is used to prevent sensitive data from leaking over the cloud by working with certain cloud technologies. It is responsible for ensuring that corporate personnel can use cloud applications comfortably without data breaches or loss.

When DLP detects data in the right format according to the rules defined for it, it blocks the action taken or tries to ensure the security of the transmission by encrypting the data. For example, credit card numbers have a certain format, and when the DLP product in the email content sees the credit card number per this format, it will take the relevant action. The following image shows how DLP works in a basic sense:

![[Pasted image 20250109161024.png]]

Important dlp : 
- Forcepoint
- McAfee
- Trend Micro
- Checkpoint
- Symantec

### Asset Management Solutions

Asset Management Solutions is software that can implement all asset management operations such as monitoring the operating status of assets in the corporate network, maintaining them, and removing them when necessary.

Thanks to Asset Management Tools, outdated software can be easily detected and managed. For example, quick action is critical when a security update arrives that patches an important vulnerability in a firewall device. Because as time passes, there may be malicious activities aimed at critical vulnerabilities. Thanks to Asset Management Tools, you can be notified about security updates quickly and updates are made quickly.

- AssetExplorer
- Ivanti
- Armis
- Asset Panda

### Web Application Firewall (WAF)

Web Application Firewall (WAF) is security software or hardware that monitors, filters, and blocks incoming packets to a web application and outgoing packets from a web application.

![[Pasted image 20250109161333.png]]

Network: a security product that is hardware-based on the relevant network. It needs staff to write rules on it and to maintain it

Host: It is a WAF with more customization possibilities. Considering that it is a software product, it consumes the resources of the server it is on. It may be more difficult to maintain and the systems on it must be securely hardened

Cloud:En cloud 

A WAF manages inbound application traffic according to existing rules on it. These requests, which belong to the HTTP protocol, are either allowed or blocked per the rules. Since it works at the application layer level, it can prevent web-based attacks. In the image below, the working logic of the WAF product is shown in a basic sense.Before going to the web application, HTTP requests from users are met in the WAF product.

![[Pasted image 20250109164923.png]]

waf:
- AWS
- Cloudflare
- F5
- Citrix
- Fortiweb


### Load Balancer

Load Balancer is a hardware or software used to distribute the traffic to the servers in a balanced way and is placed in front of the servers.

Some popular Load Balancer products used in the cyber security industry are as follows:
- Nginx
- F5
- HAProxy
- Citrix
- Azure Traffic Manager
- AWS

### Proxy Server

A proxy Server is hardware or software used for many different purposes and acts as a gateway between client and server.

![[Pasted image 20250109170001.png]]


Forward Proxy Server is the most widely used proxy server type. It is used to direct requests from a private network to the internet with a firewall.

A transparent Proxy Server is a proxy server that directs requests and responses to the target without making changes to incoming/outgoing requests and responses.

Anonymous Proxy Server is a proxy server that enables anonymous browsing on the internet.

A high Anonymity Proxy Server is a proxy server that makes it difficult to track the client with higher confidentiality without sending the proxy server type and client IP address information in the request.


A distorting Proxy Server is a proxy server that tries to hide its identity by defining itself as the proxy server of a website. By changing the real IP address, the confidentiality of the client is tried to be ensured.


Data Center Proxy Server is a special proxy server that is used as a proxy server that is not connected to the ISP (Internet Service Provider) by getting service over data centers. It is a proxy server that is insufficient to provide anonymity. It has a quick response feature.

A residential Proxy Server is a proxy server that passes all requests made by the client. Thanks to this proxy server, unwanted and suspicious advertisements can be blocked. It is more secure than other proxy servers.


A public Proxy Server is a free proxy server available to everyone. It is ideal for those looking for a cost-free proxy server by sacrificing security and speed. It's insecure because it's accessible to everyone, and it's also slow.

  
A shared Proxy Server is a proxy server that can be used by more than one person at the same time. It is preferred for fast connection and cost-free use. The disadvantage of this proxy server is that it is used by many people at the same time, so the activity of any user can affect another. For example, after the activity of one of the users, the IP address of this proxy server may be blocked by a server. In this case, access to the blocking server cannot be provided by all persons using the proxy server.

  
SSL Proxy Server is a proxy server in which the communication between client and server is provided in a bidirectional encrypted manner. It can be said to be safe because it provides encrypted communication against threats.


A rotating Proxy Server is a proxy server where a separate IP address is assigned to each client.


A reverse Proxy Server is a proxy server that validates and processes transactions so that the client does not communicate directly. The most popular reverse proxy servers are "Varnish" and "Squid".

  
A split Proxy Server is a proxy server that runs as two programs installed on two different computers.

A non-Transparent Proxy Server is a proxy server that works by sending all requests to the firewall. Clients using this proxy server are aware that requests are sent over the firewall.


A hostile Proxy Server is a proxy server used to eavesdrop on traffic between client and target on the web.


Intercepting Proxy Server is a proxy server that allows using proxy server features and gateway features together.

A forced Proxy Server is a proxy server where blocking and allowing policies are applied together.


Caching Proxy Server is a proxy server that has a caching mechanism on it and returns a response in accordance with this caching mechanism in response to the requests sent by the clients.

A web Proxy Server is a proxy server that works on web traffic.

A socks Proxy Server is a proxy server that prevents external network components from obtaining information about the client.

HTTP Proxy Server is a proxy server with caching mechanism for HTTP protocol.

Some popular Proxy Server products used in the cyber security industry are as follows:

- Smartproxy
- Bright Data
- SOAX
- Oxylabs


### Email Security Solutions

Email Security Solutions is one of the security solutions that provides security against threats that may come via e-mail. It can be software or hardware-based products.

- Ensuring the security control of the files in the email
- Ensuring security checks of URLs in the email
- Detection and blocking of spoofed emails
- Blocking known harmful emails
- Blocking email addresses with malicious content detected
- Transmitting information about harmful e-mail content to the relevant product or manager as a warning
Some popular Email Security Solutions products used within the cyber security industry are as follows:

- FireEye EX
- IronPort
- TrendMicro Email Security
- Proofpoint
- Symantec


