
Cyber ​​threat intelligence (CTI) is a cyber security discipline that aims to produce actionable output after processing and interpreting the data collected from multiple sources, and to inform organizations against cyber attacks through these outputs to minimize damages.

![[Pasted image 20250123101642.png]]

Planing and Direction : . Planning is the part that allows us to find answers to questions such as what exactly is expected from intelligence, who will consume the intelligence obtained, and which teams or individuals will take action as a result of the intelligence obtained

Utiliser les infos des attaques réussis afin de réduire les futures attaques

Les informations des attaques extérierus nous permettent de nous protéger et il est important de suivre ces informations.

Informations gathering : C'est l'ou on va collecter les informations 
- Hacker Forums
- Ransomware Blogs
- Deep/Dark Web Forums and Bot Markets
- Public Sandboxes
- Telegram/ICQ/IRC/Discord/Twitter/Instagram/Facebook/LinkedIn
- Surface Web(Cybersecurity Blogs etc.)
- Public Research Reports
- File Download Sites
- Github/Gitlab/Bitbucket etc.
- Public Buckets (Amazon S3/Azure Blob etc.)
- Shodan/Binary Edge/Zoomeye vb.
- Sources that provide IOC (Alienvault, Abuse.ch, MalwareBazaar vb.)
- Honeypots
- SIEM, IDS/IPS, Firewalls
- Public Leak Databases


Processing : On filtre les données afin d'obtenir ce dont nous avons besoin

Analysis Production : Les informations sont analysées et interprétées afin d'avoir les meilleurs résulats

Dissemination and feedback :  Diffuser et commenter les résultats

![[Pasted image 20250123103013.png]]


Déterminer sa surface d'attaque afin de mieux connaitre l'organisation.
When creating the attack surface, domains, subdomains, websites, login pages, CMS applications, technologies used on websites, IP addresses, IP blocks, DNS records, C-level employee mails, network applications, operating systems, bin numbers, and swift codes, and SSL certificates will be included. We will determine all these by proceeding through the main domain, which was provided to us by the organization as per the scenario.


Avec host.io , on peut voir les autres domaines avec la même adresse ip.
Avce viewdns , on peut regarder les noms domaines similaires afin de voir les usurpations possibles
These tools are SecurityTrails, Aquatone, Sublist3r, and Assetfinder.

Pour les sites : Wappalyser , whatsrun , whatcms , buildwith

Pour les ip : Shodan , Binaryedge , Zoomeye , Censys

Osint : Rocket Reach , Appolot , ContactOut , SalesQL



Pour les informations : 

Shodan et les sites qui lui ressemble ,

Resources such as Alienvault, Malwarebazaar, Abuse.ch, Malshare, Anyrun, Virustotal, Hybrid-Analysis, Totalhash, Phishunt, Spamhaus, Tor Exit Nodes, Urlscan, Zone-h, Rats, Sorbs, Barracuda and many more can provide us with IOCs.

Les forums de  hacker : ( à trouver)

Les blogs de Randsomware : 

Some of the most popular ransomware groups today are; Lockbit, Conti, Revil, Hive, Babuk. You can view the active ransomware groups from the link below and view the links to their blogs:  
  
http://ransomwr3tsydeii4q43vazm7wofla5ujdajquitomtd47cxjtfgwyyd.onion/


Black Markets 
Les chaines telegram discord et autres
Les répertoires de code aussi type github 

Popular sites that allow file uploading anonymously are sites such as Anonfiles, Mediafire, Uploadfiles, WeTransfer, File.io.

Public Buckets
 Kippo, Cowrite, Glastopf, Nodepot, Google Hack Honeypot, ElasticHoney, Honeymail are some of the popular honeypots.
 Chercher des rules de firewall , ids , ips ayant subi des attaques

Rassembler les trois :

- External Attack Surface Management (EASM) : connaitre sa surface d'attaque
- Digital Risk Protection (DRP)
- Cyber ​​Threat Intelligence (CTI)



