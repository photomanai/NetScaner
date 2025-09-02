import scapy.all as scapy
import optparse
import sys
from manuf import manuf
import socket
import os


def icon():
    print(
        r"""
  _   _      _    _____                                 
 | \ | |    | |  / ____|                                
 |  \| | ___| |_| (___   ___ __ _ _ __  _ __   ___ _ __ 
 | . ` |/ _ \ __|\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |\  |  __/ |_ ____) | (_| (_| | | | | | | |  __/ |   
 |_| \_|\___|\__|_____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                        
                                                by: PhotoManAi        
"""
    )


def getUserInput():
    parser = optparse.OptionParser("python3 netScanner.py -r <range> ")
    parser.add_option(
        "-r", "--range", dest="range", help="IP range 192.168.6.0/24,/16,/8"
    )
    parser.add_option(
        "-R",
        "--retry",
        dest="retry",
        default=2,
        type="int",
        help="Retry count (default=2)",
    )
    parser.add_option(
        "-t",
        "--timeout",
        dest="timeout",
        default=3,
        type="int",
        help="Timeout in seconds (default=3)",
    )
    (user_input, args) = parser.parse_args()
    if not user_input.range:
        print("Invalid argument. Use -h for help.")
        sys.exit(1)
    return (user_input, args)


def scan():
    icon()
    (user_input, args) = getUserInput()
    ip_range = user_input.range
    timeout = user_input.timeout
    retry = user_input.retry
    print(f"IP RANGE IS {ip_range}")
    arp_req_pac = scapy.ARP(pdst=ip_range)
    brodcast_pac = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # scapy.ls(scapy.Ether())
    combined_pac = brodcast_pac / arp_req_pac
    (answered, unanswered) = scapy.srp(combined_pac, timeout=timeout, retry=retry)
    return (answered, unanswered)


def main() -> None:
    (user_input, args) = getUserInput()
    ip_range = user_input.range
    (answered, unanswered) = scan()

    os.system("cls" if os.name == "nt" else "clear")

    print()
    print(f"Currently scanning: {ip_range}")
    print()
    print(
        f"Received {len(answered) + len(unanswered)} packets, "
        f"got {len(answered)} answers, "
        f"remaining {len(unanswered)} packets"
    )
    print()
    p = manuf.MacParser()
    print("{:<15} {:<20} {:<30} {}".format("IP", "MAC", "Vendor", "Hostname"))
    print("-" * 80)
    for snd, rcv in answered:
        ip = rcv.psrc
        mac = rcv.hwsrc
        vendor = p.get_manuf(rcv.hwsrc) or "Unknown vendor"
        try:
            hostname = socket.gethostbyaddr(rcv.psrc)[0]
        except:
            hostname = "Unknown"

        print("{:<15} {:<20} {:<30} {}".format(ip, mac, vendor, hostname))


if __name__ == "__main__":
    main()
