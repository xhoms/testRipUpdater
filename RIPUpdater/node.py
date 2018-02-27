import logging
import gevent

from minemeld.ft.redis import RedisSet
from netaddr import IPNetwork, AddrFormatError
from struct import Struct
from gevent import socket

LOG = logging.getLogger(__name__)
MAX_ENTRIES_PER_PACKET = 25
RIP_DSTADDR = '224.0.0.9'
RIP_PORT = '520'
RIP_UPDATE_TIME = 30
RIP_MAX_ENTRIES = 32000


class _RipUpdater(object):
    _add_counter = 0
    _rip_entry = None
    _rip_packet_header = '\x02\x02\x00\x00'
    _rip_payload = None
    _rip_socket = None
    parent_name = None

    def __init__(self, parent_name):
        self._add_counter = 0
        self._rip_entry = Struct(">HxxIIII")
        self._rip_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.parent_name = parent_name if parent_name is not None else "ripupdater"

    def _flush(self):
        self._rip_socket.sendto(self._rip_payload, (RIP_DSTADDR, RIP_PORT))
        self._rip_payload = self._rip_packet_header
        pass

    def _add_entry(self, address, netmask):
        self._rip_payload += self._rip_entry.pack(2, address, netmask, 0, 1)
        self._add_counter += 1
        if self._add_counter == MAX_ENTRIES_PER_PACKET:
            self._flush()
            self._add_counter = 0;

    def add(self, ip_addr):
        parsed = IPNetwork(ip_addr)
        self._add_entry(parsed.ip.value, parsed.netmask.value)


class RIPv2(RedisSet):
    _rip_updater_gevent = None
    _RipUpdater = None
    max_entries = RIP_MAX_ENTRIES

    def _rip_update(self):
        keep_in_loop = True
        LOG.info("{} - Starting RIPv2 updater".format(self.name))
        prefix_counter = 0
        while keep_in_loop:
            try:
                zrange = self.SR.zrange
                ilist = zrange(self.redis_skey, 0, (1 << 32) - 1)
                for i in ilist:
                    if self._discard_non_ipv4(i) is None:
                        continue
                    prefix_counter += 1
                    if prefix_counter >= self.max_entries:
                        break
                    self._RipUpdater.add(i)
                gevent.sleep(RIP_UPDATE_TIME)
            except gevent.GreenletExit:
                LOG.info("{} - Stopping RIPv2 updater".format(self.name))
                keep_in_loop = False

    def configure(self):
        super(RIPv2, self).configure()
        self._RipUpdater = _RipUpdater(self.name)
        self.max_entries = self.config.get('max_entries', 32000)

    def stop(self):
        super(RIPv2, self).start()
        self._rip_updater_gevent = gevent.spawn(self._rip_update())

    def stop(self):
        super(RIPv2, self).stop()
        self._rip_updater_gevent.kill()

    def _discard_non_ipv4(self, ip_addr):
        try:
            parsed = IPNetwork(ip_addr)
        except (AddrFormatError, ValueError):
            LOG.error('{} - Unknown IP version: {}'.format(self.name, ip_addr))
            return None

        if parsed.version == 6:
            LOG.error('{} - Does not support IPv6 local interfaces {}'.format(self.name, ip_addr))
            return None

        return ip_addr
