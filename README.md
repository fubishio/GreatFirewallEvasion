# Great FireWall Evasion

This is a personal implementation of a packet fragmentation program that is designed to circumvent the "Great Firewall" using the [Scapy](https://scapy.net/) library. It works by fragmenting a message and creating extra "fake" packets, making it hard for the "Great Firewall" to piece together the original message and block it. 

## Getting Started

Requires Python 2.7+ and [Scapy](https://scapy.net/) library. Please check [here](https://scapy.readthedocs.io/en/latest/installation.html) for installation instructions. The program must have root privileges and permissions to send packets as most machines don't give that by default. Also make sure that the router does not block traffic from this program as this could possibly stop packets from leaving the network. I personally used Ubuntu 18.04.1 LTS as a VM to develop and run this.  

### Goals
The goal of this project is to send a https request for [Falun Gong](https://en.wikipedia.org/wiki/Falun_Gong) past the Great Firewall to China's [Ministry of IT](www.miit.gov.cn) page. Falun Gong is definitely not OK in China and is known to be censored and blocked by China's Great Firewall. To bypass the firewall, I made a packet sender that fragments and creates "dummy" packets. More details in Concepts.

### Features and Usage
There are 3 functions with a corresponding main python function/caller:  
* checkfirewall(.py) - pings the target server and see if RST packets are sent back to detect whether there is a firewall there  
* traceroute(.py) - my implementation of [traceroute](https://en.wikipedia.org/wiki/Traceroute) that shows if there is an RST packet returned with a `*` in the beginning  
* frag(.py) - fragments the message/payload and sends the packets along with dummy packets with a shortened [ttl](https://en.wikipedia.org/wiki/Time_to_live) to make it harder to compute contraband messages (explained more in Concepts)  

To use, simply call either `sudo python checkfirewall.py`, `sudo python traceroute.py`, or `sudo python frag.py [number of hops]` in commandline. If this is run on Ubuntu, it is important to use sudo because sudo has the most permissions and will not run without them. To change the inputs, in the main of checkfirewall.py, traceroute.py, and frag.py, change `target = "202.106.121.6"` to target = "[destination ip]". Also you can change the content of msg.txt as that is the payload.    
To use, run:  
1. `sudo python checkfirewall.py` to check if there is a firewall there
2. `sudo python traceroute.py` to estimate at which hops the firewall would be
3. `sudo python frag.py[ttl of dummy packets]` to send the packet over where ttl is where the firewall is thought to be at   

## Concepts
The Great Firewall that I am trying to bypass refers to the on-path device that examines network packets and responds by injecting RST packets. This essentially severs a connection prematurely if it detects network behavior it doesn't like. Often times, packets will not just contain all the information in one packet and the Great Firewall must reassemble any message that spans across multiple packets. This method of circumventing the Great Firewall depends on the Great Firewall's need to reassemble messages.

### Fragmentation
The method this program uses to circumvent the firewall follows:
1. Fragment the original message  
2. Create dummy packets alongside the fragmented packets  
3. Set the dummy packets [ttl](https://en.wikipedia.org/wiki/Time_to_live) to where we estimate the Great Firewall exists  
4. Send the packets to the destination  
![illustration](https://github.com/fubishio/GreatFirewallEvasion/blob/master/screenshots/illustration.png)  
*an eye seemed apt because the firewall oversees traffic*

### Why this method works
To understand why this method works, we must first examine what exactly the firewall does. The firewall intercepts packets and reassembles them to read the original message. In this case, if the firewall sees Falun Gong, the firewall sends an RST/reset packet to the sender to shut down the connection. The firewall attempts to reassemble the message and it is here that this program circumvents it. Instead of fragmenting the message and sending it as is, this program creates a packet for every fragmented packet of the original message and sends it alongside the original packets. For example if "Falun Gong" was split into 3 packets, then there will be 3 dummy packets with other content. In this implementation, the alternative content is simply "aaaaa". When the firewall pieces it together, the reconstructed messages would look like "Faaaaaa Gong", "aaaaaaaaaaaaaaa", or any other permutations between the original packets and the dummy ones. "Faaaaaa Gong" and "aaaaaaaaaaaaaaa" are not blocked and although the firewall could possibly piece together Falun Gong, it only happens in a small percentage of attempts and can simply be run again.  
  
If the Great Firewall cannot piece together the message, there would be a problem with the recipient piecing together the message. To solve this, the dummy packets are configured with a lower ttl than the original packets. ttl is a packets allowance of hops so if the ttl is 5, then the packet can hop to at most 5 different ip's before fizzling out and disappearing. When we set the dummy packets with a lower ttl, our goal is to have them get to the Great Firewall, pass it, and fizzle out before reaching the destination. This ensures that the recipient only receives the original packets as the dummy packets should have died out by then. We just need to make sure that the ttl of the packet is greater than the hops it takes to get to the firewall but less than the hops it takes to reach the destination for this method to work. The traceroute written will provide a estimation on "where" the Great Firewall is along the route.

## Testing
The internet is not consistent enough for writing JUnit-esque tests to test my implementation because it is not guaranteed to use the same path or respond the same way everytime. Instead, to test the implementation, I wrote mains for all 3 of the functions and sent a Google search request for Falun Gong to a Chinese government website and checked outputs to make sure its consistent with expected behavior of the Great Firewall.  
Here are the expected behaviors of my written function:   
* checkfirewall - This function must return FIREWALL most of the time because anything related to Falun Gong is definitely blocked and censored by the Chinese government  
* traceroute - RST packets are sent in the middle of the hops instead of the beginning hops because a packet should not go straight from the source location to the firewall immediately. Any other behavior would indicate that my implementation failed. Also I run original traceroute in Ubuntu to make sure it looks similar.  
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
