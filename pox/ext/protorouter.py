# Import some POX stuff
from pox.core import core  # Main POX object
import pox.openflow.libopenflow_01 as of  # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr  # Address types
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


PRIVATE_SUBNET = IPAddr("192.168.1.0")  # Red interna
PRIVATE_MASK = 24  # Máscara de la red interna
PRIVATE_IP = IPAddr("192.168.1.254")  # IP del router en la red privada
PUBLIC_IP = IPAddr("200.0.0.254")  # IP del router en la red pública
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")  # MAC del router hacia la red pública
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")  # MAC del router hacia la red privada
PUBLIC_PORT = 1  # Puerto del switch conectado a la red pública

FLOW_IDLE_TIMEOUT = 30  # Segundos de inactividad antes de expirar un flujo NAT


class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        self.arp_table = {}
        self.packets_pending_arp = {}  # ip -> lista de eventos (paquetes) pendientes

        self.nat_entrante = {}
        self.nat_saliente = {}  # 5-tupla de la conexión -> puerto público ya asignado
        self.port_to_conn_key = {}  # puerto público -> 5-tupla de la conexión
        self.free_public_ports = set(
            range(10000, 65536)
        )  # pool de puertos públicos libres

    def _handle_FlowRemoved(self, event):
        port = (
            event.ofp.cookie
        )  # usamos el puerto público como cookie para identificar el flujo
        conn_key = self.port_to_conn_key.pop(port, None)
        if conn_key is not None:
            self.nat_saliente.pop(conn_key, None)
            self.nat_entrante.pop(port, None)
            self.free_public_ports.add(port)
            log_color(
                YELLOW,
                f"Flujo expirado: puerto público {port} liberado y "
                f"conexión {conn_key} eliminada de las tablas de NAT.",
            )

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning(
                "[DROP] PacketIn con trama no reconocida. "
                "POX no pudo decodificar el paquete."
            )
            return

        if event.parsed.type == ethernet.IP_TYPE:
            self.handle_ip(event)

        elif event.parsed.type == ethernet.ARP_TYPE:
            self.handle_arp(event)

        else:
            log_color(YELLOW, "Paquete ignorado: protocolo distinto de IPv4 y ARP.")

    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port

        log_color(
            YELLOW,
            f"RECIBIDO IP: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}",
        )

        # por si es icmp
        if (
            ip_pkt.protocol == ip_pkt.TCP_PROTOCOL
            or ip_pkt.protocol == ip_pkt.UDP_PROTOCOL
        ):
            transport_pkt = ip_pkt.payload
        else:
            log_color(YELLOW, "No es TCP ni UDP. Lo ignoro.")
            return

        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):

            log_color(
                GREEN,
                f"MATCH: {ip_pkt.srcip} pertenece a la red privada "
                f"{PRIVATE_SUBNET}/{PRIVATE_MASK}",
            )

            dst_mac = self.arp_table.get(ip_pkt.dstip)
            if dst_mac is None:
                log_color(
                    YELLOW,
                    f"MAC de {ip_pkt.dstip} desconocida: encolo el paquete "
                    "y resuelvo por ARP",
                )
                # FIX: resolvemos el destino PÚBLICO, con la identidad PÚBLICA,
                # por el puerto PÚBLICO
                self.queue_pending(
                    ip_pkt.dstip, event, PUBLIC_PORT, PUBLIC_MAC, PUBLIC_IP
                )
                return

            private_src_port = transport_pkt.srcport

            # Si esta misma conexión ya tenía un puerto público asignado
            # (p.ej. el flujo expiró por idle_timeout pero la conexión TCP
            # sigue viva), reusamos el mismo puerto en vez de asignar uno
            # nuevo: si no, el servidor ve paquetes con un puerto origen
            # distinto a mitad de conexión y la rechaza (RST).
            conn_key = (
                in_port,
                ip_pkt.protocol,
                ip_pkt.srcip,
                private_src_port,
                ip_pkt.dstip,
                transport_pkt.dstport,
            )
            allocated_public_port = self.nat_saliente.get(conn_key)
            if allocated_public_port is None:
                allocated_public_port = (
                    self.free_public_ports.pop()
                )  # asignamos un puerto público disponible
                self.nat_saliente[conn_key] = allocated_public_port

            self.nat_entrante[allocated_public_port] = (
                ip_pkt.srcip,
                private_src_port,
                in_port,
            )

            self.port_to_conn_key[allocated_public_port] = conn_key

            # Instalar Flujo Saliente
            fm = of.ofp_flow_mod()
            fm.idle_timeout = FLOW_IDLE_TIMEOUT
            # usamos el puerto público como cookie para identificar el flujo
            fm.cookie = allocated_public_port
            fm.flags = (
                of.OFPFF_SEND_FLOW_REM
            )  # para recibir notificación cuando el flujo expire

            # Filtro (Saliente)
            fm.match.nw_src = ip_pkt.srcip
            fm.match.dl_type = 0x800  # IPv4
            fm.match.in_port = in_port
            fm.match.nw_proto = ip_pkt.protocol
            fm.match.tp_src = private_src_port
            fm.match.nw_dst = ip_pkt.dstip
            fm.match.tp_dst = transport_pkt.dstport

            # Acción (Saliente)
            fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
            fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))

            # NAT
            fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
            fm.actions.append(of.ofp_action_tp_port.set_src(allocated_public_port))

            fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            self.connection.send(fm)

            # Reenviar paquete actual con MACs actualizadas
            # (Los posteriores pasan por flujo)
            packet.src = PUBLIC_MAC
            packet.dst = dst_mac

            # NAT
            ip_pkt.srcip = PUBLIC_IP
            transport_pkt.srcport = allocated_public_port

            msg = of.ofp_packet_out()
            msg.data = packet.pack()
            msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            log_color(
                CYAN,
                f"ENVIANDO IP: {ip_pkt.srcip} → {ip_pkt.dstip} | "
                f"MAC: {PUBLIC_MAC} → {dst_mac} | Out Port: {PUBLIC_PORT}",
            )
            self.connection.send(msg)

        elif ip_pkt.dstip == PUBLIC_IP:

            public_dst_port = transport_pkt.dstport

            if public_dst_port not in self.nat_entrante:
                return
            # Recuperamos la IP y puerto originales
            # del host privado que inició la conexión
            original_ip, original_port, original_in_port = self.nat_entrante[
                public_dst_port
            ]

            private_dst_mac = self.arp_table.get(original_ip)
            if private_dst_mac is None:
                log_color(
                    YELLOW,
                    f"MAC de {original_ip} desconocida: encolo el paquete "
                    "y resuelvo por ARP",
                )
                self.queue_pending(
                    original_ip, event, original_in_port, PRIVATE_MAC, PRIVATE_IP
                )
                return

            # Instalar Flujo Entrante (para respuesta)
            fm_back = of.ofp_flow_mod()
            fm_back.idle_timeout = FLOW_IDLE_TIMEOUT
            # usamos el puerto público como cookie para identificar el flujo
            fm_back.cookie = public_dst_port
            fm_back.flags = (
                of.OFPFF_SEND_FLOW_REM
            )  # para recibir notificación cuando el flujo expire

            # # Filtro (Entrante)
            fm_back.match.nw_src = ip_pkt.srcip
            fm_back.match.nw_dst = PUBLIC_IP
            fm_back.match.dl_type = 0x800  # IPv4
            fm_back.match.in_port = PUBLIC_PORT
            fm_back.match.nw_proto = ip_pkt.protocol

            fm_back.match.tp_dst = public_dst_port

            # # Acción (Entrante)
            fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
            fm_back.actions.append(of.ofp_action_dl_addr.set_dst(private_dst_mac))

            # NAT
            fm_back.actions.append(of.ofp_action_nw_addr.set_dst(original_ip))
            fm_back.actions.append(of.ofp_action_tp_port.set_dst(original_port))
            fm_back.actions.append(of.ofp_action_output(port=original_in_port))

            self.connection.send(fm_back)

            packet.src = PRIVATE_MAC
            packet.dst = private_dst_mac

            # NAT
            ip_pkt.dstip = original_ip
            transport_pkt.dstport = original_port

            msg = of.ofp_packet_out()
            msg.data = packet.pack()
            msg.actions.append(of.ofp_action_output(port=original_in_port))
            log_color(
                CYAN,
                f"ENVIANDO IP: {ip_pkt.srcip} → "
                f"{ip_pkt.dstip}:{transport_pkt.dstport} | "
                f"NAT: {PUBLIC_IP}:{public_dst_port} → "
                f"{original_ip}:{original_port} | "
                f"Out Port: {original_in_port}",
            )
            self.connection.send(msg)

        else:
            log_color(
                RED,
                f"NO MATCH: {ip_pkt.srcip} no pertenece a "
                f"{PRIVATE_SUBNET}/{PRIVATE_MASK}",
            )

    def queue_pending(self, ip, event, out_port, mac_address, ip_address):
        # Si ya hay paquetes esperando esa IP, no repetimos el ARP request.
        is_first = not self.packets_pending_arp.get(ip)
        self.packets_pending_arp.setdefault(ip, []).append(event)
        if is_first:
            self.send_arp_request(ip, out_port, mac_address, ip_address)

    def resolve_pending(self, ip):
        pending = self.packets_pending_arp.pop(ip, None)
        if not pending:
            return

        log_color(
            CYAN,
            f"MAC de {ip} resuelta: reprocesando {len(pending)} paquete(s) en espera",
        )
        for event in pending:
            self.handle_ip(event)

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

        log_color(
            CYAN,
            f"ENVIANDO ARP REPLY: {IP_ADDRESS} ({MAC_ADRESS}) → "
            f"{request.protosrc} ({request.hwsrc}) | Out Port: {out_port}",
        )

        self.connection.send(msg)

    def send_arp_request(self, target_ip, out_port, MAC_ADRESS, IP_ADDRESS):
        # FIX: ahora recibe directamente la IP a resolver (target_ip),
        # en vez de leerla de un objeto "request" que no la tenía.

        a = arp()
        a.opcode = arp.REQUEST

        a.hwsrc = MAC_ADRESS
        a.protosrc = IP_ADDRESS

        a.hwdst = EthAddr("00:00:00:00:00:00")
        a.protodst = target_ip

        e = ethernet()
        e.type = ethernet.ARP_TYPE
        e.src = MAC_ADRESS
        e.dst = ETHER_BROADCAST
        e.payload = a

        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))

        log_color(
            CYAN,
            f"ENVIANDO ARP REQUEST: {IP_ADDRESS} ({MAC_ADRESS}) → "
            f"{target_ip} (Broadcast) | Out Port: {out_port}",
        )

        self.connection.send(msg)

    def handle_arp(self, event):
        packet = event.parsed
        arp_pkt = packet.payload
        in_port = event.port

        arp_type = (
            "REQUEST"
            if arp_pkt.opcode == arp.REQUEST
            else (
                "REPLY" if arp_pkt.opcode == arp.REPLY else f"UNKNOWN({arp_pkt.opcode})"
            )
        )

        log_color(
            YELLOW,
            f"RECIBIDO ARP {arp_type} | "
            f"{arp_pkt.protosrc} ({arp_pkt.hwsrc}) → "
            f"{arp_pkt.protodst} ({arp_pkt.hwdst}) | "
            f"In Port: {in_port}",
        )

        # guardamos ya para la ip cual es su MAC
        self.arp_table[arp_pkt.protosrc] = arp_pkt.hwsrc

        # Si había paquetes esperando que se resuelva esta IP, los reprocesamos ahora.
        self.resolve_pending(arp_pkt.protosrc)

        if arp_pkt.opcode == arp.REQUEST:

            if arp_pkt.protodst == PRIVATE_IP:
                self.send_arp_reply(arp_pkt, in_port, PRIVATE_MAC, PRIVATE_IP)
                return

            if arp_pkt.protodst == PUBLIC_IP:
                self.send_arp_reply(arp_pkt, in_port, PUBLIC_MAC, PUBLIC_IP)
                return

            log_color(
                YELLOW,
                f"ARP request para {arp_pkt.protodst} no es para el router; ignorado.",
            )


def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
