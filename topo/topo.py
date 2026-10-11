

#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, Node
from mininet.cli import CLI
from mininet.log import setLogLevel

def connectToRootNS(network, switch, ip, routes):
    root = Node('root', inNamespace=False)
    intf = network.addLink(root, switch).intf1
    root.setIP(ip, intf=intf)
    network.start()
    for route in routes:
        root.cmd('route add -net ' + route + ' dev ' + str(intf))

def run():
    net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=True)
    net.addController('c0', controller=RemoteController,
                      ip='127.0.0.1', port=6653)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    for i in range(1, 5):
        h = net.addHost(f'h{i}', ip=f'10.0.0.{i}/24')
        net.addLink(h, s1)
    connectToRootNS(net, s1, '10.0.0.254/24', ['10.0.0.0/24'])
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
