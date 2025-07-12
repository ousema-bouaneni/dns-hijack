DNS Hijacking
====

Ousema BOUANENI

Done as part of a cybersecurity course at École polytechnique (CSC_43M05_EP)

# Program description
`dns_hijack` is a command line utility that launches a [DNS hijacking attack](https://en.wikipedia.org/wiki/DNS_hijacking) on a network interface of the user's choice.

Once you're in the root directory of the project, it can be compiled with a simple:
```console
$make
```

The usage syntax is the following:
```console
#./dns_hijack
```

# Setup description
## The network
In order to demonstrate the attack, I have set up 3 different VMs running Ubuntu Server 24.04: a victim (machine1), an attacker (machine2) and a dns server (machine3). All three machines are connected to the same network inet1 using a hub, as is illustrated by the following diagram:
```
               IP: 172.16.0.1                 
            ┌────────────────────┐             
            │  machine1 (victim) │             
            └─────────┬──────────┘             
                      │intnet1                 
                      │                        
                  ┌───┴────┐                   
        ┌─────────┤  Hub   ├─────────┐         
        │intnet1  └────────┘ intnet1 │         
        │                            │         
┌───────┴──────────┐        ┌────────┴────────┐
│machine2(attacker)│        │  machine3 (dns) │
└──────────────────┘        └─────────────────┘
   IP: 172.16.0.2              IP: 172.16.0.3  
```

The DNS server has been set up on machine3 using `dnsmasq`.
```console
#sudo apt update && sudo apt install dnsmasq
#systemctl disable --now systemd-resolved
$echo "ousema.com 1.2.3.4" >> /etc/hosts
#systemctl restart dnsmasq
```
And machine3 was set up as machine1's DNS server using netplan conf files.

## The attack
After getting the l2flood executable program into machine2 (for instance using `scp`), the effects of the attack can be illustrated by doing a DNS query before running `dns_hijack` on the attacker and afterwards (using `dig` or `nslookup` for instance), and observing the result.
```console
user@machine1:~$ dig @machine3 ousema.com

; <<>> DiG 9.18.30-0ubuntu0.24.04.2-Ubuntu <<>> @machine3 ousema.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61951
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;ousema.com.                    IN      A

;; ANSWER SECTION:
ousema.com.             0       IN      A       1.2.3.4

;; Query time: 3 msec
;; SERVER: 172.16.0.3#53(machine3) (UDP)
;; WHEN: Thu May 22 23:00:05 UTC 2025
;; MSG SIZE  rcvd: 55

user@machine1:~$ dig @machine3 ousema.com

; <<>> DiG 9.18.30-0ubuntu0.24.04.2-Ubuntu <<>> @machine3 ousema.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 24062
;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;ousema.com.                    IN      A

;; ANSWER SECTION:
ousema.com.             3600    IN      A       192.168.1.102

;; Query time: 11 msec
;; SERVER: 172.16.0.3#53(machine3) (UDP)
;; WHEN: Thu May 22 23:00:17 UTC 2025
;; MSG SIZE  rcvd: 54
```

This can be seen more clearly in the attached `demonstration.mp4` file.