"""
Aether Owl Wifi Analyzer

List nearby APs including information such as SSID, BSSID, Channel number and frequency

Author: Jonathan Sproule

PSEUDO:

Sniff on wlan0 for Dot11 probe-resp / beacons at 1 second intervals 
Print SSID, BSSID, Channel, Signal, Band
Switch channel

Scan 2.4ghz then 5ghz
"""


from scapy.all import *
import time
import os

SEEN_NETWORKS = {}

def channel_hop(interface, channel):
    """Switches Channels"""

    os.system(f"iwconfig {interface} channel {channel}")
    time.sleep(0.5)

def get_channel(packet):
    """Extract channel information from packet"""
    try:
        # check radiotap frequency
        if RadioTap in packet and hasattr(packet[RadioTap], 'ChannelFrequency'):
            freq = packet[RadioTap].ChannelFrequency
            if 2412 <= freq <= 2484:
                return int((freq - 2407) / 5)
            elif 5170 <= freq <= 5825:
                return int((freq - 5000) / 5)
        
        #check ds parameter Set
        ds = packet[Dot11Elt:3]
        if ds and ds.info:
            return int(ord(ds.info[0]))

        #check ht information
        for element in packet[Dot11Elt:]:
            # ht operation
            if element.ID == 61 and element.info:  
                return int(ord(element.info[0]))
             # vht operation
            elif element.ID == 192 and element.info: 
                seg0 = int(ord(element.info[0]))
                if seg0:
                    return seg0
                  # he operation
            elif element.ID == 35 and len(element.info) >= 2:
                return int(ord(element.info[1]))
             # ht operation
            elif element.ID == 45 and element.info: 
                return int(ord(element.info[0]))

    except Exception:
        pass
    
    return "N/A"
def get_band(CHANNEl):
    """Determine frequency band based on channel number"""

    if CHANNEl == "N/A":
        return CHANNEl
    
    try:

        CHANNEl = int(CHANNEl)

        if 1 <= CHANNEl <= 14:
            return "2.4GHz"
        elif CHANNEl in [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 
                        116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]:
            return "5GHz"
        else:
            return "Unknown"
    except:
        return "Unknown"

    
def wifi_analyzer(packet):
    """Retrieves and displays wifi info: BSSID, SSID, SIGNAL, BAND"""

    CHANNEL = None
    SSID = None
    BSSID = None
    SIGNAL = None
    BAND = None

    #if wifi packet
    if Dot11 in packet:

        #signal extraction
        if RadioTap in packet:
            try:
                SIGNAL = packet[RadioTap].dBm_AntSignal
            except:
                try:
                    SIGNAL = packet[RadioTap].dB_AntSignal
                except:
                    SIGNAL = "N/A"
    if packet.haslayer(Dot11Beacon):

        BSSID = packet[Dot11].addr3
        SSID  = packet[Dot11Elt].info.decode('utf-8', 'ignore').strip()
        if not SSID:
            SSID = "Hidden"

        CHANNEL = get_channel(packet)
        BAND = get_band(CHANNEL)

        # only print if not seen this network before
        if BSSID not in SEEN_NETWORKS:
            network_info = {
                "ssid": SSID,
                "mac": BSSID,
                "channel": CHANNEL,
                "band": BAND
            }
            
            SEEN_NETWORKS[BSSID] = network_info
            
            print(f"{str(SSID):<37} {str(CHANNEL):<14} {str(BSSID):<28} {str(SIGNAL)}dbm            {BAND}")

def scanner(interface):
        """Main analysis function: scans 2.4ghz channel range then 5ghz channel range. Once scan is complete, function sets adapter channel 1"""


        CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]

        for channel in range(1, 14) :
            sniff(iface=interface, prn= wifi_analyzer, store=0, timeout=1)
            channel_hop(interface, channel)
        
        for channel in CHANNELS_5:
            sniff(iface=interface, prn= wifi_analyzer, store=0, timeout=1)
            channel_hop(interface, channel)

        os.system(f"iwconfig {interface} channel 1")

if __name__ == "__main__":
    interface = 'wlan0'
    

    try:

            print("               ...    *    .     .\n"
                "              .       .    (*)   *\n"
                "              .      |*  ..   *   ..\n"
                "               .  * \\|  *  ___  . . *\n"
                "            *   \\/   |/ \\/{o,o}     .\n"
                "              *\\*\\   |  / /)  )* */* *\n"
                "                  \\ \\| /,--\"-\"---  ..\n"
                "            _-----`  |(,__,__/__/_ .\n"
                "                   \\ ||      ..\n"
                "                    ||| .            *\n"
                "                    |||\n"
                "            ejm98   |||\n"
                "              , -=-~' .-^- _\n"
                "                       `")
            print("Spam Ctrl + C to Quit")
            print("There can be a small delay during start up and small delays during channel switches\n")
            print("                                Aether0wl Wifi Analyzer")
            print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            print("\n     SSID                          CHANNEL                 BSSID              SIGNAL STRENGTH         BAND")
            print("--------------------            --------------       -----------------       -----------------       ------")

            scanner(interface)
    except Exception as e:
        print(f"Error during scanning: {e}")
        