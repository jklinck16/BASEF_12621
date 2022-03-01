import hashlib


def hash_file(fname):
    f = open("/Users/jeffreyklinck/Desktop/Blockchain/Test_Files/"+fname+".txt", "r")
    string = f.read()
    string_type = string[0:10]
    encoded_full = string.encode()
    result_full = hashlib.sha256(encoded_full)
    hexdigest_full = result_full.hexdigest()
    encoded_type = string_type.encode()
    result_type = hashlib.sha256(encoded_type)
    hexdigest_type = result_type.hexdigest()
    if (hexdigest_type == "7ee0a60c0f40ad8e1b4137a8fcda943a0b5da1da9e93e1f8026e2296eb38e8cb"):
        prefix = "0000"
    elif (hexdigest_type == "7ee08d468aebe9234c72219afd1d7b336e80d6b83f2a2cf91c42ba06b298ac17"):
        prefix = "0001"
    elif (hexdigest_type == "e08ea61b95762724b8ff71be1329ab5b2d807bd3638706e33cb2739d7f97dec4"):
        prefix = "0002"
    elif (hexdigest_type == "8c3bbc0c3b6401f195ca7e36849dfb7677c5ad24f4d74ec51b0f29c607a97a7f"):
        prefix = "0003"
    elif (hexdigest_type == "bc27722878ebd6af22ec4c67352dac32834128b351df52f9aa901d4847cc999f"):
        prefix = "0004"
    else:
        prefix = "0005"
    final_str = (prefix + hexdigest_full)[0:64]
    print(final_str)

hash_file("Test_1")









'''
def check_file(f1name,hash):
    hash_file(f1name)
    if (final_str == hash):
        print("Verified")
    else:
        print("Altered")

check_file("Test_1","0000c90c8e065d9f7e3f3d6a1f0ac0bbfe1000e54aee211415a2608107f69b56")
'''
