import sys, re, itertools, time
from binascii import hexlify
from threading import Thread, Event

from impacket.examples.secretsdump import LocalOperations, RemoteOperations, NTDSHashes
from impacket.smbconnection import SMBConnection, SessionError
from socket import error as socket_error


def process_remote(username, password, target, historic):
    hashes = list()

    print("Attempting to connect to {}...".format(target))
    try:
        connection = SMBConnection(target, target)
        connection.login(username, password, "", "", "")

        ops = RemoteOperations(connection, False, None)
        ops.setExecMethod("smbexec")

        stopper = Event()
        spinner = Thread(target=__update, args=(stopper, hashes))
        spinner.start()
        NTDSHashes(None, None, isRemote=True, remoteOps=ops, noLMHash=True, useVSSMethod=False,
                   justNTLM=True, printUserStatus=True, history=historic,
                   perSecretCallback=lambda type, secret: hashes.append(__process_hash(secret))).dump()
        stopper.set()
        spinner.join()

        if len(hashes) == 0:
            raise Exception("Extraction seemingly finished successfully but I didn't find any hashes...")

        return __get_domain(hashes), hashes
    except socket_error:
        raise Exception("Failed to connect to {}".format(target))
    except SessionError as e:
        if e.error == 3221225581:
            raise Exception("Username or password incorrect - please try again.")


def process_local(system, ntds, historic):
    hashes = list()

    print("Attempting to grab decryption key...")
    ops = LocalOperations(system)

    try:
        bootKey = ops.getBootKey()
    except:
        raise Exception("Failed to retrieve decryption key. Ensure your SYSTEM hive is correct.")

    print("Found key: 0x{0}.".format(hexlify(bootKey)))
    stopper = Event()
    spinner = Thread(target=__update, args=(stopper, hashes))
    spinner.start()
    NTDSHashes(ntds, bootKey, noLMHash=ops.checkNoLMHashPolicy(), useVSSMethod=True, justNTLM=True,
               printUserStatus=True, history=historic,
               perSecretCallback=lambda type, secret: hashes.append(__process_hash(secret))).dump()

    stopper.set()
    spinner.join()

    return __get_domain(hashes), hashes


def __process_hash(hash):
    user, rid, lmhash, nthash, enabled = re.findall("(?P<user>.*):(?P<rid>.*):(?P<lmhash>.*):(?P<ntlmhash>.*):::(?: \(status=(?P<enabled>.*)\))?", hash)[0]
    history_match = re.match("(?P<user>.*)(_history\d+$)", user)

    if history_match:
        user = history_match.group(1)

        return {"username": user, "ntlmhash": nthash, "password": None, "historic": True}
    else:
        return {"username": user, "ntlmhash": nthash, "password": None, "enabled": True if enabled == "Enabled" else False}


def __get_domain(hashes):
    return [hash["username"].split("\\")[0] for hash in hashes if "\\" in hash["username"]][0]


def __update(stopper, hashes):
    spinner = itertools.cycle(['-', '/', '|', '\\'])

    while not stopper.is_set():
        sys.stdout.write("[" + spinner.next() + "] (" + str(len(hashes)) + ") Finding and extracting hashes - this might take a few minutes...   \r")
        sys.stdout.flush()
        time.sleep(0.2)