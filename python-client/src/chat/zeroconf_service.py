from zeroconf import ServiceInfo, IPVersion, ServiceBrowser, ServiceStateChange, Zeroconf
import threading
import socket
import click
import time

class ZeroconfService:
    """
        This class is responsible for service registration using zeroconf (mDNS) on the local network.
    """

    def __init__(self, username):
        """
            Initializes the ZeroconfService object with the given username.
            The service is registered as <username>._closecircle._tcp.local with the 
            local ip address on port 5353.
        """
        self.local_ip = self.get_local_ip()
        self.username = username
        self.zeroconf = Zeroconf(ip_version=IPVersion.All)
        self.service_type = "_closecircle._tcp.local."
        self.service_name = f"{self.username}._closecircle._tcp.local."
        self.service_port = 5353

        self.service_info = ServiceInfo(
            self.service_type,
            self.service_name,
            addresses=[socket.inet_aton(self.local_ip)],
            port=self.service_port,
            properties={'username': self.username},
            server=f"{self.username}.local.",
        )
        self.register_service()
        self.listening_for_services = True
        self.peers = []
        self.service_listener_thread = threading.Thread(target=self.listen_for_services, daemon=True)
        self.service_listener_thread.start()
        print("Zeroconf service started.")

    def get_local_ip(self) -> str:
        """
            Attempts to determine the default local IP address.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                local_ip = s.getsockname()[0]
        except Exception as e:
            print(f"Error obtaining local IP address: {e}")
            local_ip = "127.0.0.1" #Fallback to localhost
        return local_ip

    def register_service(self) -> None:
        """
            This function registers a service with the zeroconf server.
            The service is registered with the name <username>._closecircle._tcp.local 
            on self.service_port and the local IP address.
        """
        self.zeroconf.register_service(self.service_info)
        click.echo(f'User {self.username} added to local network. Accepting connections at {self.local_ip} port 3000...')

    def on_service_state_change(self, zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange) -> None:
        """
            Callback function for handling service state changes, such as adding 
            or removing a peer from the list of peers.
        """
        if state_change is ServiceStateChange.Added:
            info = zeroconf.get_service_info(service_type, name)
            if info:
                addresses = ["%s:%d" % (socket.inet_ntoa(socket.inet_aton(addr)), info.port) for addr in info.parsed_scoped_addresses()]
                new_peer = {
                    'name': name,
                    'addresses': addresses,
                    'weight': info.weight,
                    'priority': info.priority,
                    'server': info.server,
                    'properties': info.properties
                }
                if new_peer not in self.peers:
                    self.peers.append(new_peer)
        elif state_change is ServiceStateChange.Removed:
            self.peers = [peer for peer in self.peers if peer['name'] != name]

    def listen_for_services(self) -> None:
        """
            This function continuously discovers peers on the local network.
            It operates on a separate thread, used to update the list of peers 
            using a Zeroconf service browser every second.
        """
        service_browser = ServiceBrowser(self.zeroconf, ["_closecircle._tcp.local."], handlers=[self.on_service_state_change])

        while True:
            if not self.listening_for_services:
                break
            time.sleep(1)

    def unregister_service(self) -> None:
        """
            This function unregisters the service from the zeroconf server.
        """
        self.listening_for_services = False
        self.service_listener_thread.join()
        self.zeroconf.unregister_service(self.service_info)
        self.zeroconf.close()
        print("Zeroconf service stopped.")
