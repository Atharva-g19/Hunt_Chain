from enum import Enum


class AssetType(str, Enum):
    HOSTNAME = "hostname"
    HOST_WILDCARD = "host_wildcard"
    URL = "url"
    URL_PATH_WILDCARD = "url_path_wildcard"
    IPV4 = "ipv4"
    IPV4_CIDR = "ipv4_cidr"