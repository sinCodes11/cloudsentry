"""OCI SDK wrapper for CloudSentry."""

import os
from typing import List, Optional, Generator
from pathlib import Path

import oci
from oci.config import from_file as load_oci_config
from oci.identity import IdentityClient
from oci.object_storage import ObjectStorageClient
from oci.core import ComputeClient, VirtualNetworkClient, BlockstorageClient
from oci.database import DatabaseClient
from oci.load_balancer import LoadBalancerClient

from .config import OCIConfig


class OCIClient:
    """Wrapper around OCI SDK clients."""

    def __init__(self, config: OCIConfig):
        self.oci_config = config
        self._config = self._load_config()
        self._tenancy_id = self._config["tenancy"]

        self._identity: Optional[IdentityClient] = None
        self._object_storage: Optional[ObjectStorageClient] = None
        self._compute: Optional[ComputeClient] = None
        self._network: Optional[VirtualNetworkClient] = None
        self._blockstorage: Optional[BlockstorageClient] = None
        self._database: Optional[DatabaseClient] = None
        self._load_balancer: Optional[LoadBalancerClient] = None

    def _load_config(self) -> dict:
        """Load OCI configuration from file."""
        config_path = os.path.expanduser(self.oci_config.config_file)
        return load_oci_config(config_path, self.oci_config.profile)

    @property
    def tenancy_id(self) -> str:
        return self._tenancy_id

    @property
    def identity(self) -> IdentityClient:
        if self._identity is None:
            self._identity = IdentityClient(self._config)
        return self._identity

    @property
    def object_storage(self) -> ObjectStorageClient:
        if self._object_storage is None:
            self._object_storage = ObjectStorageClient(self._config)
        return self._object_storage

    @property
    def compute(self) -> ComputeClient:
        if self._compute is None:
            self._compute = ComputeClient(self._config)
        return self._compute

    @property
    def network(self) -> VirtualNetworkClient:
        if self._network is None:
            self._network = VirtualNetworkClient(self._config)
        return self._network

    @property
    def blockstorage(self) -> BlockstorageClient:
        if self._blockstorage is None:
            self._blockstorage = BlockstorageClient(self._config)
        return self._blockstorage

    @property
    def database(self) -> DatabaseClient:
        if self._database is None:
            self._database = DatabaseClient(self._config)
        return self._database

    @property
    def load_balancer(self) -> LoadBalancerClient:
        if self._load_balancer is None:
            self._load_balancer = LoadBalancerClient(self._config)
        return self._load_balancer

    def get_compartments(self, compartment_ids: List[str]) -> List[str]:
        """Get list of compartment IDs to scan."""
        if "ALL" in compartment_ids:
            return self._get_all_compartments()
        return compartment_ids

    def _get_all_compartments(self) -> List[str]:
        """Recursively get all compartments in tenancy."""
        compartments = [self._tenancy_id]

        def _recurse(parent_id: str):
            response = self.identity.list_compartments(
                compartment_id=parent_id,
                compartment_id_in_subtree=False,
                lifecycle_state="ACTIVE",
            )
            for compartment in response.data:
                compartments.append(compartment.id)
                _recurse(compartment.id)

        _recurse(self._tenancy_id)
        return compartments

    def list_buckets(self, compartment_id: str) -> Generator:
        """List all buckets in a compartment."""
        namespace = self.object_storage.get_namespace().data
        response = self.object_storage.list_buckets(
            namespace_name=namespace,
            compartment_id=compartment_id,
        )
        for bucket_summary in response.data:
            bucket = self.object_storage.get_bucket(
                namespace_name=namespace,
                bucket_name=bucket_summary.name,
            ).data
            yield bucket

    def list_instances(self, compartment_id: str) -> Generator:
        """List all compute instances in a compartment."""
        response = self.compute.list_instances(
            compartment_id=compartment_id,
            lifecycle_state="RUNNING",
        )
        for instance in response.data:
            yield instance

    def list_security_lists(self, compartment_id: str) -> Generator:
        """List all security lists in a compartment."""
        vcns = self.network.list_vcns(compartment_id=compartment_id).data
        for vcn in vcns:
            sec_lists = self.network.list_security_lists(
                compartment_id=compartment_id,
                vcn_id=vcn.id,
            ).data
            for sec_list in sec_lists:
                yield sec_list

    def list_network_security_groups(self, compartment_id: str) -> Generator:
        """List all network security groups in a compartment."""
        vcns = self.network.list_vcns(compartment_id=compartment_id).data
        for vcn in vcns:
            nsgs = self.network.list_network_security_groups(
                compartment_id=compartment_id,
                vcn_id=vcn.id,
            ).data
            for nsg in nsgs:
                yield nsg

    def list_vcns(self, compartment_id: str) -> Generator:
        """List all VCNs in a compartment."""
        response = self.network.list_vcns(compartment_id=compartment_id)
        for vcn in response.data:
            yield vcn

    def list_users(self) -> Generator:
        """List all users in the tenancy."""
        response = self.identity.list_users(compartment_id=self._tenancy_id)
        for user in response.data:
            yield user

    def list_api_keys(self, user_id: str) -> Generator:
        """List API keys for a user."""
        response = self.identity.list_api_keys(user_id=user_id)
        for key in response.data:
            yield key

    def list_policies(self, compartment_id: str) -> Generator:
        """List IAM policies in a compartment."""
        response = self.identity.list_policies(compartment_id=compartment_id)
        for policy in response.data:
            yield policy

    def list_boot_volumes(self, compartment_id: str, availability_domain: str) -> Generator:
        """List boot volumes in a compartment."""
        response = self.blockstorage.list_boot_volumes(
            compartment_id=compartment_id,
            availability_domain=availability_domain,
        )
        for volume in response.data:
            yield volume

    def list_autonomous_databases(self, compartment_id: str) -> Generator:
        """List autonomous databases in a compartment."""
        response = self.database.list_autonomous_databases(
            compartment_id=compartment_id,
        )
        for db in response.data:
            yield db

    def list_db_systems(self, compartment_id: str) -> Generator:
        """List DB systems in a compartment."""
        response = self.database.list_db_systems(
            compartment_id=compartment_id,
        )
        for db_system in response.data:
            yield db_system

    def list_load_balancers(self, compartment_id: str) -> Generator:
        """List load balancers in a compartment."""
        response = self.load_balancer.list_load_balancers(
            compartment_id=compartment_id,
        )
        for lb in response.data:
            yield lb

    def get_availability_domains(self, compartment_id: str) -> List[str]:
        """Get availability domains for a compartment."""
        response = self.identity.list_availability_domains(
            compartment_id=compartment_id,
        )
        return [ad.name for ad in response.data]
