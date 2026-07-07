from typing import List, Optional


class BlindingFactor:
    def __init__(self, blind_bytes: bytes = bytes()):
        self.blind_bytes = blind_bytes

    @classmethod
    def from_bytes(cls, blind_bytes: bytes) -> 'BlindingFactor':
        return cls(blind_bytes)

    @classmethod
    def from_int(cls, val: int) -> 'BlindingFactor':
        return cls(val.to_bytes(32, 'big'))

    def to_bytes(self) -> bytes:
        return self.blind_bytes

    def to_int(self) -> int:
        return int.from_bytes(self.blind_bytes, 'big')


def pedersen_blind_sum(blinds: List[BlindingFactor]) -> Optional[BlindingFactor]:
    """
    Adds Pedersen commitment blinding factors together, handling them as integers.
    
    :param blinds: A list of byte strings representing blinding factors.
    :return: A byte string representing the sum of the blinding factors, or None if any are invalid.
    """
    # Order of the secp256k1 curve
    secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    accumulator = 0  # Start with an additive identity element.
    
    for blind in blinds:
        # Convert the blind factor from bytes to an integer
        current_scalar = blind.to_int()
        
        # Check if the current scalar is a valid secp256k1 scalar
        if current_scalar >= secp256k1_order:
            return None
        
        # Add current scalar to the accumulator
        accumulator = (accumulator + current_scalar) % secp256k1_order
    
    # Convert the accumulated scalar back to bytes
    accumulator_bytes = accumulator.to_bytes(32, 'big')
    
    # Return the resulting scalar as a 32-byte big-endian byte string.
    return BlindingFactor(accumulator_bytes)
