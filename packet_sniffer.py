# Import necessary modules from the scapy library
from scapy.all import sniff, IP, TCP, UDP

# Define a function to process captured packets
def process_packet(packet):
    """
    This function is called whenever a packet is captured.
    It processes the packet to extract and display relevant information.
    """
    # Check if the packet has an IP address layer
    if IP in packet:
        # Extract the source and destination IP address from the packet
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        # Check if the packet has a TCP layer in it
        if TCP in packet:
            print("Protocol: TCP")
            # Extract the TCP layer from the packet
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"Payload: {tcp_layer.payload}")
        
        # Check if the packet has a UDP layer
        elif UDP in packet:
            print("Protocol: UDP")
            # Extract the UDP layer from the packet
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            print(f"Payload: {udp_layer.payload}")
        
        # Print a separator for better readability
        print("-" * 40)

# Define a function to start sniffing packets on a specific interface
def start_sniffing(interface):
    """
    This function starts the packet sniffing process on the specified network interface.
    """
    print(f"Starting packet sniffing on interface {interface}...")
    # Start sniffing on the specified interface
    # prn specifies the callback function to call for each captured packet
    # store=False specifies that packets should not be stored in memory
    sniff(iface=interface, prn=process_packet, store=False)

# Main entry point of the script
if __name__ == "__main__":
    # Replace 'eth0' with your network interface name
    # Common interface names: 'eth0' for Ethernet, 'wlan0' for Wi-Fi on Linux
    start_sniffing('eth0')
