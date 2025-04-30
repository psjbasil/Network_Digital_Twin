from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI

class NetworkTopo(Topo):
    def build(self):
        # Create switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Create hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')  
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')

        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s3)
        self.addLink(h4, s2)  
        self.addLink(h5, s1)
        self.addLink(h6, s3)
        self.addLink(s1, s2)
        self.addLink(s2, s3)

def create_network():
    topo = NetworkTopo()
    net = Mininet(
        topo=topo,
        controller=RemoteController('c0', ip='127.0.0.1', port=6653)
    )
    return net 

if __name__ == '__main__':
    net = create_network()
    net.start()
    CLI(net)
    net.stop() 