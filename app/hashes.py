import hashlib

BLOCKSIZE = 65536


def obtain_md5(file):
    hasher = hashlib.md5()
    with open(file, "rb") as mdfile:
        buf = mdfile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = mdfile.read(BLOCKSIZE)
    return hasher.hexdigest()


def obtain_sha1(file):
    hasher = hashlib.sha1()
    with open(file, "rb") as mdfile:
        buf = mdfile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = mdfile.read(BLOCKSIZE)
    return hasher.hexdigest()


def obtain_sha256(file):
    hasher = hashlib.sha256()
    with open(file, "rb") as mdfile:
        buf = mdfile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = mdfile.read(BLOCKSIZE)
    return hasher.hexdigest()
