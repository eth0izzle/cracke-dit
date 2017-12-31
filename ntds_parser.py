import sys, re, itertools, time
from binascii import hexlify
from threading import Thread, Event

from impacket.examples.secretsdump import LocalOperations, NTDSHashes


def process(system, ntds, historic):
    hashes = list()

    print("Attempting to grab decryption key...")
    ops = LocalOperations(system)

    try:
        bootKey = ops.getBootKey()
    except:
        raise Exception("Failed to retrieve decryption key. Ensure your SYSTEM hive is correct.")

    print("Found key: 0x{0}.".format(hexlify(bootKey)))
    stopper = Event()
    spinner = Thread(target=update, args=(stopper, hashes))
    spinner.start()
    NTDSHashes(ntds, bootKey, noLMHash=ops.checkNoLMHashPolicy(), useVSSMethod=True, justNTLM=True,
               printUserStatus=True, history=historic,
               perSecretCallback=lambda type, secret: hashes.append(__process_hash(secret))).dump()

    stopper.set()
    spinner.join()

    domain = hashes[-1]["username"].split("\\")[0]

    return domain, hashes


def __process_hash(hash):
    user, rid, lmhash, nthash, enabled = re.findall("(?P<user>.*):(?P<rid>.*):(?P<lmhash>.*):(?P<ntlmhash>.*):::(?: \(status=(?P<enabled>.*)\))?", hash)[0]
    history_match = re.match("(?P<user>.*)(_history\d+$)", user)

    if history_match:
        user = history_match.group(1)

        return {"username": user, "ntlmhash": nthash, "password": None, "historic": True}
    else:
        return {"username": user, "ntlmhash": nthash, "password": None, "enabled": True if enabled == "Enabled" else False}


def update(stopper, hashes):
    spinner = itertools.cycle(['-', '/', '|', '\\'])

    while not stopper.is_set():
        sys.stdout.write("[" + spinner.next() + "] (" + str(len(hashes)) + ") Finding and extracting hashes - this might take a few minutes...   \r")
        sys.stdout.flush()
        time.sleep(0.2)