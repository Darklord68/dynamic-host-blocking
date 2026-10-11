from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.util import connectToRootNS

def run():
    net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=True)
    net.addController('c0', controller=RemoteController,
                      ip='127.0.0.1', port=6653)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    for i in range(1, 5):                       # h1 server, h2 attacker, h3 normal, h4 admin
        h = net.addHost(f'h{i}', ip=f'10.0.0.{i}/24')
        net.addLink(h, s1)
    net.start()
    connectToRootNS(net, s1, '10.0.0.254', ['10.0.0.0/24'])  # hosts can reach controller side at 10.0.0.254
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
