# Router-Simulation
Created a router simulation in C to demonstrate packet redirection using ARP and ICMP protocols. Enhanced understanding of networking and protocol layering with Ethernet and IP.

# Steps Taken In Implementation

I wanted to make debugging easier by enabling the use of printf statements when performing ping tests. As a result, the first step was to implement the ARP Request. This involved verifying that the received packet contained an ARP header of type request and processing the header by exchanging the source IP/MAC addresses with the destination addresses, making the destination address the new source. Also updated the header type to "reply" and sent the packet back with the new header. <br>

Next, I implemented ARP Reply to receive responses to requests. To do this, I stored the IP and MAC addresses received in the ARP table for later use. I also determined the best route to forward IP packets and sent the pending packets to the "next hop" address found. <br>

To test the functionality of the project, I implemented IPV4, which involved verifying the received packet had an IPV4 header and ensuring that it was valid. If it was, I calculated the best route to forward the packet and decremented the time-to-live (TTL) before sending the packet further. If the MAC address of the "next hop" is unknown, an ARP request is sent and it starts waiting for a response. <br>

Finally, I implemented ICMP for "Time exceeded," "Destination unreachable," and "Echo request" cases. In these cases, I processed an ICMP header by exchanging the source and destination addresses to ensure that the error would reach the source. <br>
