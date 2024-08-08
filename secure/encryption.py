import numpy as np

password = "k8GXD9vXvZvJRwEdsun7M4Sv"

DEFAULT_PASSWORD = np.array([ord(char) for char in password]).reshape((6, 4))


def __xor_keys(keys:list):
    full_matrix = np.full((4, 6), 0xFF, dtype=np.uint8)
    keys = keys + [255] * (24-len(keys))
    full_matrix = np.array(keys).reshape((4, 6)).T
    return np.bitwise_xor(DEFAULT_PASSWORD,full_matrix)

def __create_multiplication_matrix(keys):
    multiplied = 1
    for i in keys : multiplied = multiplied * i
    # byte by byte convertion 
    byte_array = hex(multiplied).replace("0x","")
    integer_values = [int(byte,16) for byte in byte_array]
    integer_values = integer_values + [255] * (24-len(integer_values))
    full_matrix = np.array(integer_values).reshape((4,6))
    return full_matrix

def __parse_results(matrix_r,matrix_m):
    results = []
    last_matrix = np.dot(matrix_r,matrix_m)
    for l in last_matrix.flat : 
        results.append(int(hex(int(l)).replace("0x","")[0:2],16))
    return results[:24]

def __convert_keys(keys:list):
    keys = [int(key,16) for key in keys]
    return keys

def __list_int_to_bytes(int_list):
    if len(int_list) != 24:
        raise ValueError("The list must contain exactly 24 integers.")

    for i in int_list:
        if not (0 <= i <= 255):
            raise ValueError("Each integer must be in the range 0-255.")

    key = bytes(int_list)
    return key

def generate_encryption_key(keys:list[str]) -> list:
    """
    A function that generate an encryption key, a list of 24 bytes which will be used to either decrypt or encrypt with AES-192.

    This is a type of masked-aes encryption where we use dynamic key each this will help

    input:
        keys: a list of n strings shall be on hex between 00 and FF.
                n shall be less then 12 and higher then 8 for a proper generation.
    
    return:
        a list of 24 bytes that can be used with the function decypher and encrypt.
    """
    hex_keys = __convert_keys(keys)
    matrix_m = __create_multiplication_matrix(hex_keys)
    matrix_r = __xor_keys(hex_keys)
    l = __parse_results(matrix_r,matrix_m)
    return __list_int_to_bytes(l)
