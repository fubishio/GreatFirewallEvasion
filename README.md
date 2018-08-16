# Great FireWall Evasion

This is a personal implementation of a packet fragmentation program that is designed to circumvent the "Great Firewall" using the [Scapy](https://scapy.net/) library. It works by fragmenting a message and creating extra "fake" packets, making it hard for the "Great Firewall" to piece together the original message and block it. 

## Getting Started

Requires Python 2.7+ and [Scapy](https://scapy.net/) library. Please check [here](https://scapy.readthedocs.io/en/latest/installation.html) for installation instructions. The program must have root privileges and must have permissions to send packets as many machines don't give that to you by default. I used Ubuntu 18.04.1 LTS as a VM but should work on any machine with correct environment and permissions set up.

### Goals
The goal of this project is to send a https request for [Falun Gong](https://en.wikipedia.org/wiki/Falun_Gong) past the Great Firewall to China's [Ministry of IT](www.miit.gov.cn) page. Falun Gong is definitely not OK in China and is known to be censored and blocked by China's Great Firewall. To bypass the firewall, I made a packet sender that fragments and creates "dummy" packets. More details in Concepts.

### Features and Usage
There are 3 functions with a corresponding main python function/caller:  
* checkfirewall(.py) - pings the target server and see if RST packets are sent back to detect whether there is a firewall there  
* traceroute(.py) - my implementation of [traceroute](https://en.wikipedia.org/wiki/Traceroute) that shows if there is an RST packet returned with a `*` in the beginning  
* frag(.py) - fragments the message/payload and sends the packets along with dummy packets with a shortened ttl(time to live) to make it harder to compute contraband messages (explained more in Concepts)  

To use, you simply call either `sudo python checkfirewall.py`, `sudo python traceroute.py`, or `sudo python frag.py [number of hops]` in commandline. If you are on Ubuntu, it is important to use sudo because sudo has the most permissions and will not run without them. If you would like to change the inputs, in the main of checkfirewall.py, traceroute.py, and frag.py, you should change `target = "202.106.121.6"` to target = "[destination ip]". Also you can change the content of msg.txt as that is the payload.    
You should  
1. `sudo python checkfirewall.py` to check if there is a firewall there
2. `sudo python traceroute.py` to estimate at which hops the firewall would be
3. `sudo python frag.py[number of hops]` to send the packet over where number of hops is where you think the firewall is   

## Concepts

## Testing
The internet is not consistent enough for writing JUnit-esque tests to test my implementation because it is not guaranteed to use the same path or respond the same way everytime. Instead, to test the implementation, I wrote mains for all 3 of the functions and sent a Google search request for Falun Gong to a Chinese government website and checked outputs to make sure its consistent with expected behavior of the Great Firewall.  
Here are the expected behaviors of my written function:   
* checkfirewall - I know this function must return FIREWALL most of the time because Falun Gong search request is definitely blocked by Chinese government  
* traceroute - RST packets are sent in the middle of the hops instead of the beginning hops because a packet should not go straight from your location to the firewall immediately. Any other behavior would indicate that my implementation failed. Also I run original traceroute in Ubuntu to make sure it looks similar.  
* frag - It should get a 404 request back because information about Falun Gong cannot possibly be on the Chinese government website. I run it and see if I get a response back from the Chinese government website because if the connection is closed with an RST packet, nothing will be returned.

### What it looks like in action

Here's what the functions should look like when called:  
checkfirewall:  
![checkfirewall](https://github.com/fubishio/GreatFirewallEvasion/blob/master/screenshots/checkfirewall.PNG)  
traceroute:  
![traceroute](https://github.com/fubishio/GreatFirewallEvasion/blob/master/screenshots/traceroute.PNG)  
frag succeeds:  
![frag succeeds](https://github.com/fubishio/GreatFirewallEvasion/blob/master/screenshots/fragsuccess.png)  
frag fails:  
![frag fails](https://github.com/fubishio/GreatFirewallEvasion/blob/master/screenshots/fragfail.png)  

\* The hops I entered was 15 so it was `sudo python frag.py 15`  
\** In checkfirewall it shows "sent 1 packets", this is because the setting for verbose is true/1. It was not on in screenshots of traceroute and frag. To show these messages please set verbose in common.py to 1.  
![verbose](https://github.com/fubishio/GreatFirewallEvasion/blob/master/screenshots/verbose.PNG)

## Acknowledgements

Thanks to friend Ryan for teaching me about interfaces in Python and how to implement it for this project.
