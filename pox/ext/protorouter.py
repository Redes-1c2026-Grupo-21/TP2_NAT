# Import some POX stuff
from pox.core import core                       # Main POX object
import pox.openflow.libopenflow_01 as of        # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr   # Address types
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST

from pox.lib.packet.arp import arp

log = core.getLogger()
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")


PRIVATE_SUBNET = IPAddr("192.168.1.0")      # Red interna
PRIVATE_MASK = 24                           # Máscara de la red interna
PRIVATE_IP = IPAddr("192.168.1.254")        # IP del router en la red privada
PUBLIC_IP = IPAddr("200.0.0.254")           # IP del router en la red pública
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")   # MAC del router hacia la red pública
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")  # MAC del router hacia la red privada
PUBLIC_PORT = 1                             # Puerto del switch conectado a la red pública

#H1_MAC = EthAddr("00:00:00:00:00:01")       # MAC del host externo (TODO: resolver mediante ARP)


class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        self.arp_table = {}

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning("[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete.")
            return

        if event.parsed.type == ethernet.IP_TYPE:
            self.handle_ip(event)

        if event.parsed.type == ethernet.ARP_TYPE:
            self.handle_arp(event)
        
        else:
            log_color(YELLOW, f"Paquete ignorado: protocolo distinto de IPv4 y ARP.")

    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port

        log_color(
            YELLOW, f"RECIBIDO IP: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}")

        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):

            log_color(GREEN, f"MATCH: {ip_pkt.srcip} pertenece a la red privada {PRIVATE_SUBNET}/{PRIVATE_MASK}")

            # Instalar Flujo Saliente
            fm = of.ofp_flow_mod()
            fm.idle_timeout = 10

            # Filtro (Saliente)
            fm.match.nw_src = ip_pkt.srcip
            fm.match.dl_type = 0x800  # IPv4
            fm.match.in_port = in_port

            # Acción (Saliente)
            fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
            fm.actions.append(of.ofp_action_dl_addr.set_dst(self.arp_table.get(ip_pkt.dstip)))
            fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            self.connection.send(fm)

            # Instalar Flujo Entrante (para respuesta)
            fm_back = of.ofp_flow_mod()
            fm_back.idle_timeout = 10

            # Filtro (Entrante)
            fm_back.match.nw_src = ip_pkt.dstip
            fm_back.match.nw_dst = ip_pkt.srcip
            fm_back.match.dl_type = 0x800  # IPv4
            fm_back.match.in_port = PUBLIC_PORT

            # Acción (Entrante)
            fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
            fm_back.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
            fm_back.actions.append(of.ofp_action_output(port=in_port))
            self.connection.send(fm_back)

            # Reenviar paquete actual con MACs actualizadas (Los posteriores pasan por flujo)
            packet.src = PUBLIC_MAC
            packet.dst = self.arp_table.get(ip_pkt.dstip) 
            msg = of.ofp_packet_out()
            msg.data = packet.pack()
            msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            log_color(CYAN, f"ENVIANDO: {ip_pkt.srcip} → {ip_pkt.dstip} | MAC: {PUBLIC_MAC} → {self.arp_table.get(ip_pkt.dstip)} | Out Port: {PUBLIC_PORT}")
            self.connection.send(msg)

        else:
            log_color(RED, f"NO MATCH: {ip_pkt.srcip} no pertenece a {PRIVATE_SUBNET}/{PRIVATE_MASK}")


    def send_arp_reply(self, request, out_port, MAC_ADRESS, IP_ADDRESS):
        
        a = arp()
        a.opcode = arp.REPLY

        # El router responde
        a.hwsrc = MAC_ADRESS
        a.protosrc = IP_ADDRESS

        # Datos del host que hizo el request
        a.hwdst = request.hwsrc
        a.protodst = request.protosrc

        e = ethernet()
        e.type = ethernet.ARP_TYPE
        e.src = MAC_ADRESS
        e.dst = request.hwsrc
        e.payload = a

        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))

        self.connection.send(msg)

    def send_arp_request(self, ip):

        a = arp()
        a.opcode = arp.REQUEST
        a.hwsrc = PUBLIC_MAC
        a.protosrc = PUBLIC_IP
        a.hwdst = EthAddr("00:00:00:00:00:00")
        a.protodst = ip

        e = ethernet()
        e.type = ethernet.ARP_TYPE
        e.src = PUBLIC_MAC
        e.dst = ETHER_BROADCAST
        e.payload = a

        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))

        log_color(CYAN, f"ENVIANDO ARP REQUEST: {PUBLIC_IP} ({PUBLIC_MAC}) → {ip} (Broadcast) | Out Port: {PUBLIC_PORT}")

        self.connection.send(msg)

    def handle_arp(self, event):
        packet = event.parsed
        arp_pkt = packet.payload
        in_port = event.port

        log_color(
            YELLOW, f"RECIBIDO ARP: {arp_pkt.opcode} | "
            f"{arp_pkt.protosrc} ({arp_pkt.hwsrc}) → {arp_pkt.protodst} ({arp_pkt.hwdst}) | In Port: {in_port}")

        self.arp_table[arp_pkt.protosrc] = arp_pkt.hwsrc
    
        if arp_pkt.opcode == arp.REQUEST:

            if arp_pkt.protodst == PRIVATE_IP:
                self.send_arp_reply(arp_pkt, in_port, PRIVATE_MAC, PRIVATE_IP)

                return
            
            if arp_pkt.protodst == PUBLIC_IP:
                self.send_arp_reply(arp_pkt, in_port, PUBLIC_MAC, PUBLIC_IP)

                return

            if arp_pkt.protodst not in self.arp_table:
                self.send_arp_request(arp_pkt.protodst)


def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
