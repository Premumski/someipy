# Copyright (C) 2024 Felix K.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import e2e

import asyncio
from typing import Set, Tuple

from someipy._internal.someip_message import SomeIpMessage
from someipy.service import Service

from someipy._internal.tcp_client_manager import TcpClientManager, TcpClientProtocol
from someipy._internal.message_types import MessageType
from someipy._internal.return_codes import ReturnCode
from someipy._internal.someip_sd_builder import (
    build_stop_offer_service_sd_header,
    build_subscribe_eventgroup_ack_entry,
    build_subscribe_eventgroup_ack_sd_header,
)
from someipy._internal.someip_header import SomeIpHeader
from someipy._internal.someip_sd_header import (
    SdService,
    TransportLayerProtocol,
    SdEventGroupEntry,
    SdIPV4EndpointOption,
)
from someipy._internal.service_discovery_abcs import (
    ServiceDiscoveryObserver,
    ServiceDiscoverySender,
)
from someipy._internal.simple_timer import SimplePeriodicTimer
from someipy._internal.utils import (
    create_udp_socket,
    EndpointType,
    endpoint_to_str_int_tuple,
)
from someipy._internal.logging import get_logger
from someipy._internal.subscribers import Subscribers, EventGroupSubscriber
from someipy._internal.someip_endpoint import (
    SomeipEndpoint,
    TCPSomeipEndpoint,
    UDPSomeipEndpoint,
)
from someipy.server_service_instance import ServerServiceInstance

_logger_name = "server_service_instance_e2e"

class ServerServiceInstancee2e(ServerServiceInstance):
    def __init__(
        self,
        service: Service,
        instance_id: int,
        endpoint: EndpointType,
        protocol: TransportLayerProtocol,
        someip_endpoint: SomeipEndpoint,
        ttl: int = 0,  # TTL used for SD Offer entries
        sd_sender=None,
        cyclic_offer_delay_ms=2000,
    ):
        super().__init__(service, instance_id, endpoint, protocol, someip_endpoint, ttl, sd_sender, cyclic_offer_delay_ms)
        self._e2e_headers: dict[Tuple[int, int], bytes] = {}  # Initialize the E2E headers dictionary

    def last_event_e2e_header(self, event_group_id: int, event_id: int, e2e_profil: int):
        # Create a unique key for the event group and event ID
        key = (event_group_id, event_id)

        # Check if the event has occurred before
        if key not in self._e2e_headers:
            # Initialize the E2E header with the specified bytes
            if e2e_profil == 6:
                self._e2e_headers[key] = bytes([0x00, 0x00, 0x00, 0x0D, 0xFF])
            else:
                raise NotImplementedError(f"E2E profile {e2e_profil} is not implemented")
            get_logger(_logger_name).debug(
                f"Initialized E2E header for event group {event_group_id}, event {event_id} with profile {e2e_profil}"
            )

        # Return the E2E header for the event
        return self._e2e_headers[key]   

    def update_e2e_header(self, event_group_id: int, event_id: int, e2e_header: bytes):
        # Create a unique key for the event group and event ID
        key = (event_group_id, event_id)

        # Update the E2E header for the event
        self._e2e_headers[key] = e2e_header
        get_logger(_logger_name).debug(
            f"Updated E2E header for event group {event_group_id}, event {event_id} "
        )

    def send_event_e2e(self, event_group_id: int, event_id: int, e2e_profil: int, data_id: int = 0, payload: bytes = bytes([0x00])) -> None:
        """
        Sends an event to subscribers with the given event group ID, event ID, and payload.

        Args:
            event_group_id (int): The ID of the event group.
            event_id (int): The ID of the event.
            e2e_profil (int): The E2E profile which the some/ip load should be sent with. 
            data_id (int): A Data ID is needed for some E2E profiles, it is optional and defaults to 0.
            payload (bytes): The payload of the event. Can be manually crafter or serialized using someipy serialization.

        Returns:
            None: This function does not return anything.

        Note:
            - The client id and session id are set to 0x00 and 0x01 respectively.
            - The protocol version and interface version are set to 1.
        """

        self._subscribers.update()

        # Session ID is a 16-bit value and should be incremented for each method call starting from 1
        self._session_id = (self._session_id + 1) % 0xFFFF
        
        length = 8 + len(payload)     
        
        if e2e_profil == 6:
            length = length + 5
        else:
            raise ValueError(f"E2E profile {e2e_profil} not supported") 

        someip_header = SomeIpHeader(
            service_id=self._service.id,
            method_id=event_id,
            length=length,
            client_id=0x00,
            session_id=self._session_id,
            protocol_version=1,
            interface_version=self._service.major_version,
            message_type=MessageType.NOTIFICATION.value,
            return_code=0x00,
        ) 

        data = bytearray(someip_header.to_buffer()[8:] + self.last_event_e2e_header(event_group_id, event_id, e2e_profil) + payload)
        e2e.p06.e2e_p06_protect(data,len(data) - 2, data_id, offset = 8 , increment_counter = True)
        payload = bytes(data[8:])
        self.update_e2e_header(event_group_id, event_id, data[8:13])      
        

        for sub in self._subscribers.subscribers:
            # Check if the subscriber wants to receive the event group id
            if sub.eventgroup_id == event_group_id:
                get_logger(_logger_name).debug(
                    f"Send event for instance 0x{self._instance_id:04X}, service: 0x{self._service.id:04X} to {sub.endpoint[0]}:{sub.endpoint[1]}"
                )
                self._someip_endpoint.sendto(
                    someip_header.to_buffer() + payload,
                    endpoint_to_str_int_tuple(sub.endpoint),
                )
    
async def construct_server_service_instance_e2e(
    service: Service,
    instance_id: int,
    endpoint: EndpointType,
    ttl,
    sd_sender: ServiceDiscoverySender,
    cyclic_offer_delay_ms=2000,
    protocol=TransportLayerProtocol.UDP,
) -> ServerServiceInstancee2e:
    """
    Asynchronously constructs a ServerServiceInstance. Based on the given transport protocol, proper endpoints are setup before constructing the actual ServerServiceInstance.

    Args:
        service (Service): The service associated with the instance.
        instance_id (int): The ID of the instance.
        endpoint (EndpointType): The endpoint for the instance containing IP address and port.
        ttl (int, optional): The time-to-live for the instance used for service discovery offer entries. A value of 0 means that offer entries are valid for infinite time.
        sd_sender (Any, optional): The service discovery sender.
        cyclic_offer_delay_ms (int, optional): The delay in milliseconds for cyclic offers. Defaults to 2000.
        protocol (TransportLayerProtocol, optional): The transport layer protocol for the instance. Defaults to TransportLayerProtocol.UDP.

    Returns:
        ServerServiceInstance: The constructed ServerServiceInstance.

    Raises:
        None
    """
    if protocol == TransportLayerProtocol.UDP:
        loop = asyncio.get_running_loop()
        rcv_socket = create_udp_socket(str(endpoint[0]), endpoint[1])

        _, udp_endpoint = await loop.create_datagram_endpoint(
            lambda: UDPSomeipEndpoint(), sock=rcv_socket
        )

        server_instance = ServerServiceInstancee2e(
            service,
            instance_id,
            endpoint,
            TransportLayerProtocol.UDP,
            udp_endpoint,
            ttl,
            sd_sender,
            cyclic_offer_delay_ms,
        )

        udp_endpoint.set_someip_callback(server_instance.someip_message_received)

        return server_instance

    elif protocol == TransportLayerProtocol.TCP:

        # Create a TcpClientManager, a TcpClientProtocol and a TCP server
        # The TcpClientProtocol handles incoming (or lost) connections and will (de)register them
        # in the TcpClientManager. The TcpClientProtocol also handles incoming data and will trigger
        # the callback in the TcpClientManager which will forward the callback to the ClientServiceInstance.
        tcp_client_manager = TcpClientManager()
        loop = asyncio.get_running_loop()
        server = await loop.create_server(
            lambda: TcpClientProtocol(client_manager=tcp_client_manager),
            str(endpoint[0]),
            endpoint[1],
        )

        tcp_someip_endpoint = TCPSomeipEndpoint(server, tcp_client_manager)

        server_instance = ServerServiceInstancee2e(
            service,
            instance_id,
            endpoint,
            TransportLayerProtocol.TCP,
            tcp_someip_endpoint,
            ttl,
            sd_sender,
            cyclic_offer_delay_ms,
        )

        tcp_someip_endpoint.set_someip_callback(server_instance.someip_message_received)

        return server_instance
   
