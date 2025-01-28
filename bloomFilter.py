import hashlib
from bitarray import bitarray

class BloomFilter:
    def __init__(self, size, hash_count):
        """
        Initialize the Bloom filter.

        size: Number of bits in the bit array
        hash_count: Number of hash functions to use
        """
        self.size = size
        self.hash_count = hash_count
        self.bit_array = bitarray(size)
        self.bit_array.setall(0)

    def _hash(self, item, seed):
        """
        Custom complex hash function combining multiple hash algorithms.

        item: The item to hash
        seed: A seed value to vary the hash result
        return: An integer hash value
        """
        # Combine SHA-256 and MD5 with the seed
        sha256_hash = hashlib.sha256((item + str(seed)).encode()).hexdigest()
        md5_hash = hashlib.md5((item + str(seed)).encode()).hexdigest()

        # Mix the two hashes to create a new hash value
        combined = sha256_hash + md5_hash
        hash_value = int(combined, 16)  # Convert the hex string to an integer
        return hash_value % self.size

    def add(self, item):
        """
        Add an item to the Bloom filter.

        item: The item to add
        """
        for i in range(self.hash_count):
            digest = self._hash(item, i)
            self.bit_array[digest] = True

    def check(self, item):
        """
        Check if an item is in the Bloom filter.

        item: The item to check
        return: True if the item might be in the set, False if it is definitely not in the set
        """
        for i in range(self.hash_count):
            digest = self._hash(item, i)
            if not self.bit_array[digest]:
                return False
        return True


if __name__ == "__main__":
    bloom = BloomFilter(size=10000, hash_count=4)

    bloom.add("hello")
    bloom.add("world")

    print(bloom.check("hello"))
    print(bloom.check("world"))  
    print(bloom.check("python")) 
