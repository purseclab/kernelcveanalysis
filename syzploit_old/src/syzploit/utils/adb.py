"""
ADB utilities for Cuttlefish instance management.

Provides:
- calculate_adb_port: Calculate ADB port from Cuttlefish instance number
- get_adb_target: Get ADB target string (host:port) from instance number
"""

# Default ADB base port for Cuttlefish
ADB_BASE_PORT = 6520

# Default host for ADB connections
ADB_DEFAULT_HOST = "0.0.0.0"


def calculate_adb_port(instance: int) -> int:
    """
    Calculate the ADB port for a given Cuttlefish instance number.
    
    Cuttlefish instances use ports starting at 6520 for instance 1,
    6521 for instance 2, etc.
    
    Args:
        instance: Cuttlefish instance number (1-based)
        
    Returns:
        ADB port number
        
    Example:
        >>> calculate_adb_port(1)
        6520
        >>> calculate_adb_port(5)
        6524
    """
    if instance < 1:
        raise ValueError(f"Instance number must be >= 1, got {instance}")
    return ADB_BASE_PORT + (instance - 1)


def get_adb_target(instance: int, host: str = ADB_DEFAULT_HOST) -> str:
    """
    Get the ADB target string for a given Cuttlefish instance.
    
    Args:
        instance: Cuttlefish instance number (1-based)
        host: Host address for ADB connection (default: 0.0.0.0)
        
    Returns:
        ADB target string in format "host:port"
        
    Example:
        >>> get_adb_target(1)
        '0.0.0.0:6520'
        >>> get_adb_target(5, "localhost")
        'localhost:6524'
    """
    port = calculate_adb_port(instance)
    return f"{host}:{port}"


def parse_adb_target(target: str) -> tuple:
    """
    Parse an ADB target string into host and port.
    
    Args:
        target: ADB target string in format "host:port"
        
    Returns:
        Tuple of (host, port)
        
    Example:
        >>> parse_adb_target("0.0.0.0:6524")
        ('0.0.0.0', 6524)
    """
    if ':' not in target:
        raise ValueError(f"Invalid ADB target format: {target}")
    host, port_str = target.rsplit(':', 1)
    return host, int(port_str)


def instance_from_port(port: int) -> int:
    """
    Calculate the Cuttlefish instance number from an ADB port.
    
    Args:
        port: ADB port number
        
    Returns:
        Cuttlefish instance number (1-based)
        
    Example:
        >>> instance_from_port(6520)
        1
        >>> instance_from_port(6524)
        5
    """
    if port < ADB_BASE_PORT:
        raise ValueError(f"Port {port} is below ADB base port {ADB_BASE_PORT}")
    return (port - ADB_BASE_PORT) + 1
