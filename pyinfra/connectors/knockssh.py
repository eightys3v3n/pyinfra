from typing_extensions import TypedDict
from subprocess import run

from pyinfra import logger
from pyinfra.api.exceptions import ConnectError, PyinfraError

from .base import DataMeta
from .ssh import SSHConnector
from .ssh import ConnectorData as SSHConnectorData
from .ssh import connector_data_meta as ssh_connector_data_meta


class ConnectorData(SSHConnectorData):
    knock_sequence: list[int]


class KnockSSHConnector(SSHConnector):
    """
    The ``@knockssh`` connector allows you to use the SSH connector after knocking to open the SSH port.
    """

    __example_doc__ = """
    An inventory file (``inventory.py``) containing a single SSH target with a port knock of 1111, 2222.

    .. code:: python
        
        hosts = [
            ("@sshknock/my-host.net", {"knock_sequence": [1111, 2222]),
        ]
    """

    handles_execution = True

    data_cls = ConnectorData
    data_meta = {
        'knock_sequence': DataMeta("Port knocking sequence"),
        'ip_version': DataMeta("IPv6 or IPv4"),
        **ssh_connector_data_meta,
    }
    data = ConnectorData

    @staticmethod
    def make_names_data(name):
        yield "@knockssh/{0}".format(name), {"ssh_hostname": name}, []

    def connect(self) -> None:
        # Port knock before trying to connect
        args = [
            'nmap',
            '-Pn',
            '--host-timeout', '201',
            '--max-retries', '0',
            self.data['ssh_hostname'],
        ]
        if 'ip_version' in self.data and self.data['ip_version'] == 'IPv6':
            args.insert(3, '-6')

        logger.debug(f"Global nmap args for this host: {args}")
        try:
            for port in self.data['knock_sequence']:
                logger.debug(f"Port knocking host {self.host} on port {port}")

                new_args = [*args, '-p', str(port)]
                run(new_args, check=True)
        except PyinfraError as e:
            raise ConnectError(e.args[0])
        
        super().connect()
